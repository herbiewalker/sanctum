# Sanctum — Runbook

> **Status: live, v0.1.1.** Written to be followed cold by an operator who did not build the
> service. If a step here fails to work in practice, that is a runbook bug and lands as a
> same-commit fix (principle 3 / lesson L14).

Sanctum is a **companion service** to Tryst. It ingests, verifies, retains, and restores encrypted
`TRYSTBK1` backup files. The phone is the system of record; Sanctum is the second copy. This
runbook is what you read at 2 a.m. when the backup you needed is here somewhere.

---

## What Sanctum needs on the host

Sanctum is a single-container, LAN-only service (D-12). It is host-agnostic — the same image runs
on any of your Unraid boxes with the paths pointed appropriately. Prerequisites:

- **Docker + docker-compose** (Unraid ships both).
- **A tmpfs mount** big enough for the largest expected backup + the live SQLite index — 512 MiB
  is fine for a home-lab. The compose file wires this automatically; the F01 startup check
  refuses to boot if it isn't tmpfs (hard constraint 2 backstop).
- **Two appdata paths** on the host (three if you use the optional Unraid dashboard bell, see step 4):
  - `inbox/` — where Syncthing/SMB/SAF deliver `.tryst` files. Mounted **read-only** into the
    container.
  - `vault/` — where Sanctum stores its ciphertext blobs and sealed index. Writable.
  - `notify/` — optional: where Sanctum drops JSON alert intents for the host User Script (D-18). Writable.

---

## Deploy (first time on a new host)

### Quick path: the published image

Most people should do this and skip the build steps below.

1. Create the folders and give the vault to the container user:
   ```bash
   mkdir -p /mnt/user/appdata/sanctum/{inbox,vault}
   chown -R 65532:65532 /mnt/user/appdata/sanctum/vault
   ```
2. **Unraid:** add the container from [`deploy/unraid-template.xml`](deploy/unraid-template.xml)
   (repository `ghcr.io/herbiewalker/sanctum:stable`), fill in the paths, port and notification URL, and
   apply. **Compose:** copy [`.env.example`](.env.example) to `.env`, then
   `docker compose pull && docker compose up -d`.
3. Continue at **First unlock** below. Pin an exact version (for example `0.1.1`) instead of `:stable`
   if you want to choose when to update.

The rest of this section is for building from source and for Compose Manager setups.

### 1. Clone the repo and set up appdata

```bash
mkdir -p /mnt/user/appdata/sanctum
cd /mnt/user/appdata/sanctum
git clone https://github.com/herbiewalker/sanctum.git repo
cd repo
```

Create the three data dirs and confirm ownership:

```bash
mkdir -p /mnt/user/appdata/sanctum/{inbox,vault,notify}
# Sanctum runs as uid/gid 65532 inside the container (hard constraint 6).
chown -R 65532:65532 /mnt/user/appdata/sanctum/{vault,notify}
# Inbox is written by Syncthing/SMB/the operator — leave it whatever your
# share config expects, but make sure the container can READ it. The compose
# file mounts it :ro.
chmod 750 /mnt/user/appdata/sanctum/vault
```

**Share permissions matter (R3):** anyone who can write to the inbox share can hand Sanctum a
hostile file (fine — that is the T6 threat model, and ingest rejects it), but anyone who can
write to the **vault** share can delete blobs. Sanctum detects deletion but cannot prevent it.
Restrict the vault share to trusted accounts only.

### 2. Create the `.env`

```bash
cp .env.example .env
$EDITOR .env
```

Edit at minimum:

- `SANCTUM_BIND_IP` — set to the host's LAN IP (or leave `127.0.0.1` and reach it via the Unraid
  GUI's host header).
- `SANCTUM_PORT` — pick a free port.
- The three `*_PATH` variables — point them at the appdata paths you created.
- `TZ` — your zone.

**Do NOT put a passphrase, key, or token in `.env`.** By design (hard constraint 3 / D-4) there
is no environment variable that unlocks the vault. The passphrase is typed by a human at the
web UI on every start.

### 3. Build the image and start

**Most installs should pull the published image** (`ghcr.io/herbiewalker/sanctum:stable`, via the
Unraid template or `docker compose pull`). The steps below are for building from source: the compose
file's `build:` stanza handles it in one shot, but Compose Manager and plain `docker compose` need
slightly different setups.

#### 3A. Compose Manager (recommended, matches your Immich workflow)

Compose Manager keeps its compose files in `/boot/config/plugins/compose.manager/projects/<name>/`,
which is **not** the repo. So the compose file needs to know where the Dockerfile lives — via
the `SANCTUM_BUILD_CONTEXT` env variable pointing at the cloned repo.

1. In the Unraid GUI → **Docker** tab → scroll to **Compose Manager** → **Add New Stack** →
   name it `sanctum`.
2. Click ⚙ on the new stack → **Edit Stack** → **Compose File** tab. Paste the contents of
   `docker-compose.yml` from the repo — either
   [the raw file on GitHub](https://github.com/herbiewalker/sanctum/blob/main/docker-compose.yml)
   or `cat /mnt/user/appdata/sanctum/repo/docker-compose.yml` on the box.
3. Same dialog → **Stack env file** tab. Paste
   [`deploy/unraid.env.example`](deploy/unraid.env.example) verbatim — it's the paste-and-go
   Unraid template (sensible defaults, correct paths, port 8250, LAN bind). If your appdata
   sits under a path other than `/mnt/user/appdata/sanctum/`, edit the four `*_PATH` lines
   and `SANCTUM_BUILD_CONTEXT` to match.
4. Save → **Compose Up** button. First run builds the image (~1-2 min: pulls the
   digest-pinned base, compiles Go, done). Subsequent Ups reuse the built image; a **Force
   Rebuild** toggle in the UI re-builds.

#### 3B. SSH from inside the repo

If your compose file lives inside the cloned repo (e.g. you `cd` into `repo/`), the default
`build: context: .` handles it — no env var needed:

```bash
cd /mnt/user/appdata/sanctum/repo
docker compose up -d --build
docker compose logs -f
```

#### Healthy start

Either way, a good start logs:

```json
{"level":"INFO","msg":"notify drop directory","path":"/data/notify"}
{"level":"INFO","msg":"sanctum listening","addr":":8080","state":"locked","unlock_url":"..."}
```

The container is now **LOCKED** (D-4). It serves `/healthz` and the unlock page and nothing else.

Verify:

```bash
curl http://<host>:<port>/healthz
# {"status":"ok","state":"locked"}
```

### 4. Set up notifications (one setting)

Sanctum sends its own alerts (ADR D-20). Paste ONE URL into `SANCTUM_NOTIFY_URL` in the stack
env (on Unraid: the **Notification URL** field of the template):

| You use | URL form |
|---|---|
| ntfy.sh or your own ntfy over https | `ntfy://ntfy.sh/your-private-topic` |
| ntfy on your LAN over http | `ntfy+http://192.168.1.10:8081/sanctum` |
| ntfy with an access token | `ntfy://:tk_yourtoken@host/topic` |
| Discord | the channel's webhook URL (`https://discord.com/api/webhooks/...`) |
| Slack | the incoming-webhook URL (`https://hooks.slack.com/services/...`) |
| anything else | any `https://` URL; Sanctum POSTs the alert as JSON |

Several can be given, comma-separated (up to four); an alert counts as delivered if any one works.
The URL is a credential: keep it in the stack env only, never in git, and rotate it if it leaks.
Sanctum never logs it; the startup log shows only the channel kind and host.

**Test it before trusting it** (principle 12, a notification path that has never fired is not
a notification path):

```bash
docker exec sanctum /usr/local/bin/sanctum -notify-test
```

It prints `notify-test: delivered` and your phone or channel should show "Sanctum: test
notification". Alerts carry only timestamps, day counts and version numbers, never backup
contents, owner names or file names.

With no URL set, Sanctum still shows warnings in the web UI (vault locked for a long time, newest
backup past the stale limit) and logs a startup warning, but nothing will reach you off the page.

**Optional: Unraid dashboard bell via the host script (ADR D-18).** If you also want alerts in
the Unraid GUI, add a bind mount `/mnt/user/appdata/sanctum/notify:/data/notify` and the env
`SANCTUM_NOTIFY_DIR=/data/notify`, then install `deploy/unraid-scripts/sanctum-notify-dispatch.sh`
as a User Script scheduled `*/2 * * * *`. It needs only bash and sed (Unraid has no `python3`).
Files piling up in `pending/` mean the script isn't running; `failed/` suffixes (`.parse_failed`,
`.notify_failed`) say why.

---

## First unlock + first-owner provisioning

> Before you unlock, **save the passphrase in your password manager**. There is no recovery. D-4
> makes this a deliberate design property: the operator's passphrase is the single root of trust
> for the sealed index and every backup password stored inside it. See
> [CRITICAL_ASSETS.md](CRITICAL_ASSETS.md), row 1.

1. Open `http://<host>:<port>/` in a browser on the LAN. **Do this first-run setup yourself, right
   after the container starts:** on a brand-new vault, whoever reaches the unlock page first chooses
   the passphrase, then the owner login. Until you have, keep the port off the LAN. For normal use, bind `SANCTUM_BIND_IP` to the server's LAN IP rather than `0.0.0.0` (D13); for setup, use `127.0.0.1`
   or a firewalled interface).
2. Type the **vault passphrase** you just saved. Wrong attempts are rate-limited (N16: 5-attempt
   burst, 1/minute refill), so a typo won't lock you out but a scanner won't get anywhere either.
3. On a fresh vault the login page will offer to **provision the first owner**:
   - Display name — a display name (keep it neutral per D-10 — think "alice", not the real name).
   - Login username — how you'll log in from now on.
   - Login passphrase — a *different* passphrase from the vault-unlock one. This is the
     per-owner credential (D-14).
4. After provisioning, log in as the owner. (On a brand-new vault the first screen is "Create your vault": type the passphrase twice. Nothing is created if the two differ.)
5. **Add at least one backup password** under Passwords: this is the Tryst-side passphrase your
   `.tryst` files were exported with. Sanctum needs it to open new ingests. You can add more
   later (D-13 — Sanctum keeps a set, so a Tryst password rotation doesn't break ingest).
   Optionally add a **hint** to each to jog your memory later (never the password itself).

Confirm:

```bash
curl http://<host>:<port>/healthz
# {"status":"ok","state":"unlocked"}
```


---

## Using the web interface

- **Backups.** Stat tiles show the count, the newest backup and whether it is on time or overdue, the
  total size on disk, and when the newest was last verified. The table lists each backup with a
  Download button. The "What do these columns mean?" and "How do I restore a backup?" panels explain
  the rest.
- **Upload.** Choosing a file and pressing **Upload and check** shows a progress bar for the transfer,
  then a moving bar while Sanctum checks that the backup opens (this can take a minute for large files,
  because each saved password is tried in turn). **Cancel upload** works during the transfer. If your
  browser blocks scripts the form still works, just without the bar.
- **Passwords.** Each saved Tryst password has a label and an optional **hint**. Hints are stored only
  inside the encrypted index, shown only after you sign in, and never sent in alerts. Keep them vague:
  a hint is not a place for the password or anything that would let a stranger guess it. A hint that
  contains the password itself is dropped.
- **Theme.** The footer has Auto, Light and Dark. Auto follows the system setting; the choice is kept
  in a small cookie on that browser.
- **Locking.** **Lock vault** seals the index and zeroes the key at once; **Log out** only ends your
  session.
---

## Post-reboot checklist

Sanctum boots LOCKED after every start (D-4), including every unattended Unraid reboot. The
failure mode is silent: a locked vault ingests nothing and looks fine to browsers that don't try
to log in. Three things catch it:

- The **locked-since alert** (D-18) fires after `SANCTUM_LOCKED_ALERT_AFTER_HOURS` (default 24 h)
  through the Unraid notification channel — assuming the dispatcher is installed and
  test-fired.
- The **staleness alert** fires per-owner when the newest backup ages past the per-owner
  threshold (`SANCTUM_STALENESS_DAYS`, default 30 d) — but only while the vault is unlocked to
  evaluate it.
- The compose HEALTHCHECK reports `unhealthy` if the port stops answering, but says nothing
  about locked vs unlocked. Watch `/healthz` if you want an explicit "locked" indicator.

**After every reboot**, log in and unlock. If you cannot immediately, expect the locked-since
alert within a day and act on it.

---

## Ingest: dropping a backup

Two paths, both go through the same pipeline (M3):

- **Inbox drop** — drop the `.tryst` file into your `SANCTUM_INBOX_PATH` (via Syncthing, SMB,
  SAF on the phone). Sanctum's watcher polls every 5 s with a 2 s stability window; when the
  file stops growing, it ingests. Wait ~15 s, then check the UI.
- **Browser upload** — choose the file on the Backups page and press **Upload and check**. Same pipeline; a progress bar shows the transfer and then the check.

A successful ingest appears in the UI status; a rejection appears in Sanctum's log with a
neutral reason code (never a password, never a filename that leaks content — N15). See the
"failed ingest" section below.

---

## Verify it is actually working

- **UI status page** (`/status`) shows, per owner: number of stored backups, newest ingest date,
  last successful full re-verify date, verify status. This is the F14 information feed.
- **Full re-verification** happens on the scheduler (`SANCTUM_VERIFY_EVERY_HOURS`, default 168 h
  = weekly). Each blob's SHA-256 sidecar is re-checked AND a trial decrypt is attempted with the
  stored password. A failure sends a `verify_failed` notification through the dispatcher.
- **A failed verification** shows in the UI as status `hash_mismatch` or `decrypt_failed`. Blobs
  are immutable (D-11) — Sanctum will not "fix" one. Either:
  - The underlying disk is failing → check SMART, replace the disk. Sanctum's phone-side copy is
    still intact.
  - The password set no longer contains a working entry → add the older passphrase under
    Passwords; the next verify pass picks it up.
  - The blob was tampered with (T3) → the phone is still the system of record. Restore from
    phone, ingest a fresh backup, prune the tampered one.
- **Live smoke tests** (before a release, and after changing the image or the Extra Parameters):
  run `scripts/smoke-live.sh` on the Docker host as root. It starts a throwaway container with a
  scratch vault (never your real `sanctum`) and checks that Sanctum refuses to start without a tmpfs,
  rejects a 600 MB upload with 413 and flat memory, reports a tampered manifest and a below-floor
  KDF, and unlocks again once the manifest is restored. Exit code 0 means all passed. Use
  `IMAGE=<image>` to test a specific image.

---

## Backup and restore

### Getting a backup out of Sanctum

Backups are stored as the original `TRYSTBK1` bytes, byte-for-byte identical to what Tryst wrote
(D-11). Restore is a copy-out with a SHA-256 header for verification.

1. Log in, go to **Backups** for the owner.
2. Click **Download** on the backup you want. The response carries an
   `X-Sanctum-SHA256: <hex>` header.
3. Save the file. Verify:
   ```bash
   sha256sum tryst-backup-*.tryst
   # compare against the X-Sanctum-SHA256 header
   ```

### The restore drill (M6 exit criterion — do this before trusting the vault)

A restore verified only by hash is not verified (lesson L14). The whole point of Sanctum is that
a phone loss doesn't lose the data — so the round-trip must be proven end-to-end.

1. Get a backup out (above).
2. Transfer the file to your Pixel (Syncthing, USB, SAF).
3. In Tryst: **Settings → Restore backup → pick the file → enter the Tryst backup password**.
4. Confirm the record count matches what the UI's status page showed for that backup's
   `encounters` table.

A restore that opens in Tryst is a real restore. A restore that only matches a hash is a file
copy.

### Rebuilding the index from blobs (F12 — the D-5 recovery path)

Use when both `index.sealed` and `index.sealed.prev` are unrecoverable but the blob directory
under `vault/blobs/<owner>/` is intact.

What the rebuild recovers:

- `backup` rows — one per blob that verifies (SHA-256 sidecar matches) AND opens under one of
  the passwords you supply. SHA-256, size, container version, KDF iterations, and Tryst schema
  version come out of the file itself.
- `backup_table_count` rows — including the `__media__` synthetic row (D-15). Counts only, per
  DATA_MODEL — no encounter content lands in the index at any point.

What the rebuild CANNOT recover, and why:

- **Owner labels** and **owner login credentials** (`login_username`, KDF hash, salt). These
  live only in the sealed index. Rebuild inserts a placeholder `owner` row with the label
  `"<unrecovered — re-provision credentials>"` and RANDOM UNUSABLE login credentials so
  the FK holds and the placeholder cannot accidentally be logged into. You must run the
  operator "reset owner credentials" flow before that owner can sign in again.
- **The D-13 password set** (`owner_backup_password` rows). Sanctum has to be told the
  passwords again — pass them to Rebuild as candidates, and add them through the UI once the
  vault is up. Passwords that opened blobs during rebuild will be recognised again on the
  next unlock; passwords that never opened anything are still needed if the owner will ingest
  more backups later.
- **Historical `event` rows** — the rebuild only writes new `rebuild_ok`/`rebuild_skipped_*`
  events, not the earlier audit trail. That trail is a bookkeeping loss, not a data loss.

Failure modes:

- **`ErrRebuildNoPasswords`** — vault has blobs but you passed no candidate passwords. This is
  deliberate: an empty rebuild in a populated vault would look like everything was lost when
  in fact you just need to supply the passphrase.
- **`BlobsSkipped`** — the blob's SHA-256 sidecar did not match, or the structural parse
  failed. Blobs are immutable (D-11), so the on-disk file stays put; investigate whether the
  underlying filesystem is failing before assuming the data itself is gone.
- **`BlobsUnopenable`** — every candidate password failed. Either the password rotated at some
  point and you have not yet supplied the older one, or the blob is silently corrupt in a way
  the AEAD catches (which the SHA-256 side missed — unlikely but possible).

---

## Upgrade and rollback

Nothing updates Sanctum automatically, by design (D-19). Read the [CHANGELOG](CHANGELOG.md) first, and
**snapshot `vault/` before any update that touches the index schema** (the changelog says when).

**Published-image installs (the normal case).**

1. Stop the container and copy the vault: `cp -a vault vault.pre-<version>`.
2. Update: in Unraid use the Docker tab's update check or force update; with Compose run
   `docker compose pull && docker compose up -d`. Pin `SANCTUM_VERSION=x.y.z` in the env file (or an
   exact tag in the template) to control when you move.
3. The vault is locked after the restart. Unlock it, sign in, and confirm your backups are listed and
   the footer shows the new version.

To hear about new releases, set `SANCTUM_UPDATE_CHECK=true`. It is a read-only check that notifies
through `SANCTUM_NOTIFY_URL`.

**Source-build installs.**

```bash
cd /mnt/user/appdata/sanctum/repo
git fetch --tags && git checkout <new-tag>
docker compose up -d --build
```

**Rollback.** Stop the container, restore the pre-update `vault/` snapshot, and start the previous
version (`docker compose` with the old `SANCTUM_VERSION`, or `git checkout <previous-tag>` and
rebuild). Unlock as normal.

**Index schema versions.** The sealed index is upgraded in place when you unlock, with additive
migrations only. v0.1.1 moved it from schema 1 to 2 (adds the optional password `hint` column; existing
passwords get an empty hint). The older v0.1.0 should still open a v2 index because the change only
adds a column, but a snapshot is the only guaranteed way back. The `.prev` file is one seal
generation, not a snapshot. If a migration ever goes badly wrong, rebuild-from-blobs (F12) is the
last resort; see [DATA_MODEL.md](docs/DATA_MODEL.md) "Schema / migration rules".

---

## Moving Sanctum to a different Unraid host

Four things move; one stays.

**Move:**
1. The `vault/` directory (blobs + sealed index + manifest + state.json).
2. The `notify/` directory (only if there are un-dispatched intents in `pending/`).
3. The `.env` file (paths + tunables — no secrets).
4. The dispatcher User Script installation.

**Stays (in your head / password manager):**
- The vault passphrase.
- The owner login passphrase.
- The Tryst backup passphrase(s).

Procedure:

```bash
# On the OLD host:
docker compose down                # container releases file locks
tar -C /mnt/user/appdata/sanctum -czf sanctum-move.tgz vault notify .env repo/.env

# Move the tarball to the new host (SCP, USB, whatever).

# On the NEW host:
mkdir -p /mnt/user/appdata/sanctum
tar -C /mnt/user/appdata/sanctum -xzf sanctum-move.tgz
cd /mnt/user/appdata/sanctum
git clone https://github.com/herbiewalker/sanctum.git repo
cd repo
git checkout <same-tag-as-old-host>
docker compose build
docker compose up -d

# Install the dispatcher User Script on the new host (see Deploy → step 4).

# Unlock via the UI with the SAME vault passphrase.
```

If unlock fails on the new host with `ErrManifestOutOfBand` rather than `ErrBadPassphrase`, the
manifest was corrupted in transit. Restore `vault/manifest.json` from the tarball again.

---

## Emergency: the vault won't unlock

Three distinct errors have three distinct meanings. Read the log carefully.

- **`ErrBadPassphrase`** — the passphrase you typed doesn't match. This is the common case
  (typo). Re-type carefully; rate limit resets every minute.
- **`ErrManifestOutOfBand`** (F05) — `manifest.json` no longer matches the seal it produced.
  Either someone (or a filesystem gremlin) rewrote the manifest, or you moved to a new host
  and the manifest didn't come along cleanly. Restore `manifest.json` from a backup of
  `vault/`. If you don't have one, the sealed index is unrecoverable — go to F12
  rebuild-from-blobs.
- **`ErrKDFBelowProductionFloor`** (F03) — the manifest's KDF params are below Sanctum's
  production floor (Argon2id `t≥3`, `m≥64 MiB`, `p≥1`). This should never happen from normal
  use; a manifest with weak params was hand-edited, or a bug set `TestParams` on a prod vault.
  Restore the manifest from a backup of `vault/`. There is no override switch, by design.

---

## Known failure modes

> Every incident becomes a row here. The 2 a.m. fix is not done until it is written down —
> folklore does not survive six months, tables do (Phase 5).

| Symptom | Cause | Fix |
|---------|-------|-----|
| Power loss or kill while unlocked | The index is sealed to disk every 10 s when it changed, and right after each ingest (D01), so at most the last few seconds of changes are lost; backups themselves are already immutable blobs. | Start the container and unlock as normal. If a backup you uploaded in the last seconds is missing from the list, upload it again. |
| A large upload looks stuck at "Checking that the backup opens" | Each saved password is tried in turn with a slow key derivation (about 600,000 rounds), so a big file with several saved passwords can take a minute or more. | Wait. If it ends in "no password in your set can open it", add the password the backup was made with and upload again. |
| Passwords page shows a "Hint" column after an update | v0.1.1 upgraded the sealed index to schema 2 on first unlock. Expected. | Nothing to do. |
