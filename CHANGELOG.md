# Changelog

All notable changes to Sanctum are recorded here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).

> The version is **never** hand-written into a tag. The tag is the last step of a release script
> (principle 6 / lesson L1), `scripts/release.sh`.

## [Unreleased]

## [0.1.1] - 2026-11-11

### Changed — web interface redesigned
- **New look, same pages.** A clean card layout with a state pill, a tabbed header, stat tiles on the
  Backups page, plain-language copy, empty states and friendlier timestamps (`2026-11-08 14:03 UTC`).
  Jargon such as ADR and requirement numbers is out of the page text.
- **Built-in help.** Question-mark tooltips on the fields that need explaining, and "learn more" panels
  that answer the obvious questions (why unlock after every restart, what the columns mean, what happens
  when a password is deleted, how to restore).
- **Works in any browser at any size.** Responsive from 280 px phones to wide desktops; tables become
  stacked cards on narrow screens so nothing scrolls sideways; light and dark themes follow the system;
  keyboard and screen-reader friendly (skip link, labelled controls, visible focus). No JavaScript and no
  external fonts or images, so it also works offline on a LAN. Deleting a password is now a two-step
  button instead of a script dialog.
- **Stricter browser security headers (new).** Every page sends a Content-Security-Policy that allows no
  scripts, no outside resources, no framing and only same-site form posts. Tests assert the templates stay
  script-free and the header stays strict.

### Fixed — audit nits D10 to D15
- **Discord alerts can no longer ping the channel (D10):** an owner label like `@everyone` was interpolated
  into the stale-backup message; the payload now disables mention parsing. Truncation no longer splits a
  multi-byte character.
- **Update-check tag parsing is digits-only (D11):** `v+1.+2.+3` is rejected.
- **Alert-hour settings are range-checked (D12):** `SANCTUM_LOCKED_ALERT_AFTER_HOURS` and
  `..._DEBOUNCE_HOURS` must be 0 (disabled) or between 1 minute and 1 year; out-of-range values are an
  error at startup instead of silently disabling the alert or overflowing. **Behaviour change** for anyone
  who set a value outside that range.
- **Docs (D13, D14):** bind `SANCTUM_BIND_IP` to the server's LAN IP; stale "not published to a registry"
  text removed.
- **`scripts/smoke-live.sh` (D15):** the memory check now takes real readings (before and after the
  upload) and fails if it cannot; it used to print 0 MiB.

## [0.1.0] - 2026-11-11

First release: everything below was built before it. Image `ghcr.io/herbiewalker/sanctum:0.1.0` and `:stable`.

### Security — Go 1.26.11 (2026-11-11)
- Go toolchain 1.26.10 -> 1.26.11 (`go.mod`, `SETUP.md`) and the Dockerfile builder image re-pinned by
  digest, for GO-2026-6859 in `net/http` (found by `govulncheck` in CI; reachable through the update
  check and the HTTP server).

### Security — pre-release delta-audit fixes (2026-11-10, `docs/AUDIT.md` Pass 008)
- **The index is now sealed while unlocked, not only on lock (D01).** A power loss or kill used to lose
  every owner, password and backup row created in the session. The vault now checkpoints every 10 s
  (when changed) and right after each ingest.
- **Unlock no longer fails open (D02).** If `index.sealed` was missing but `.prev`/`.tmp` existed (a crash
  inside the seal rotation), any passphrase opened an empty vault. It now authenticates against the
  surviving generation.
- **Rate limiting uses the TCP peer address (D03).** `X-Forwarded-For` was trusted from anyone, so the
  unlock/login limiters could be bypassed by rotating the header.
- **One ingest at a time (D09).** A second concurrent upload gets HTTP 503 instead of filling the tmpfs
  that also holds the live index.
- **Release pipeline (D04-D06):** only tags on `main` publish; only the highest tag moves `:stable`; the
  image is built once, pushed by digest, scanned, then tagged; Trivy is pinned to a commit. Provenance
  attestation is skipped on private repos (not supported there).
- **`.dockerignore` added (D07)** so local `.env`, `*.tryst`, `inbox/` and `vault/` never enter a build.
- **Removed `deploy/unraid-scripts/sanctum-update.sh` (D08):** the host-side updater is gone. It could build
  and run fetched code as root-adjacent Docker, duplicated the container's own opt-in update check, and
  would have needed a release-signing key to be safe. Updates are manual: pull the image, or
  `git checkout <tag>` and `docker compose up -d --build`.

### Fixed — oversize uploads were staged twice on the tmpfs (2026-11-09)
- The first live smoke run (`scripts/smoke-live.sh`) showed a refused 600 MB upload still peaking at
  648 MiB: `ParseMultipartForm` wrote the body to a temp file on the tmpfs before the cap could fire, and
  ingest then staged a second copy, so any upload cost ~2x its size in tmpfs (and a legitimate 512 MiB
  backup needed ~1 GiB of tmpfs for two copies of one file). `/upload` now rejects on a declared
  `Content-Length` over the cap before reading anything, and otherwise streams the file part straight
  into ingest's single staging copy, still bounded by `MaxBytesReader`. New tests cover the declared and
  the chunked (no length) oversize cases. Also added: `scripts/smoke-live.sh`, the audit's runtime smokes
  (F01 tmpfs refusal, F02 413, F05 tampered manifest, F03 KDF floor) for a throwaway container on the host.

### Fixed — Tryst container v2 backups were rejected (2026-11-06)
- Tryst has written container version 2 since QOL-5 (v0.6.x); Sanctum only accepted version 1, so every
  current backup failed with a misleading "not a valid TRYSTBK1, or no password can open it". v2 uses
  the same crypto as v1 (the only difference is an optional `settings.json` in the ZIP, stored unread), so
  the header check now accepts versions 1 and 2. A genuinely unknown version now says so ("newer Tryst
  than this Sanctum understands") instead of blaming the password. Found live: a real post-v0.6.5 backup.

### Fixed — upload OOM-killed the container (2026-11-06)
- Ingesting a real backup got the container killed (exit 137, `OOMKilled=true`). The upload is staged on
  the `/tmp` tmpfs, which counts against the cgroup memory limit, and the decrypted body is also held in
  an in-memory buffer, so peak use is roughly 2-3x the backup size. The 512M memory / 512m tmpfs defaults
  could not ingest anything over ~150 MB. Defaults are now 2G memory / 1g tmpfs (compose, env examples,
  Unraid template). Streaming the trial decrypt to cut the peak is a possible later change.

### Added — Docker-tab polish (2026-11-05)
- `deploy/icon.png` (generated by `deploy/icon/make-icon.ps1`) and the template `Icon`; compose labels
  `net.unraid.docker.icon` / `.webui` so Compose Manager stacks get the icon and a WebUI entry too.

### Added — type-it-twice setup (2026-11-05)
- A brand-new vault now asks for the passphrase twice ("Create vault"), and owner provisioning asks
  for the login passphrase twice. A mismatch creates nothing. Before this, whatever was typed at the
  first unlock silently became the passphrase, so a typo made the vault unrecoverable (it happened).
  Existing vaults still show the single unlock box. `Vault.FirstRun()` = no sealed index on disk.

### Added — built-in notifications (2026-11-05, ADR D-20)
- `SANCTUM_NOTIFY_URL`: Sanctum posts alerts itself to ntfy, Discord, Slack or a generic webhook, so
  no host script is needed. The URL is treated as a credential (never logged or put in an error;
  redirects refused). Fan-out succeeds if any channel does. `sanctum -notify-test` sends a test.
- Web UI banners: the unlock page says how long the vault has been locked; the status page warns
  when the newest backup is past the stale limit.
- The D-18 drop directory is now optional (off unless `SANCTUM_NOTIFY_DIR` plus a mount are added);
  the Unraid template and compose no longer require a notify folder.

### Fixed (notifications)
- The update check's notifications would have been rejected as an invalid kind; `update` and `test`
  are now valid intent kinds.

### Added — published image (2026-11-05, ADR D-19)
- `.github/workflows/release.yml`: a `vX.Y.Z` tag runs tests and guards, scans the image with
  Trivy, then pushes `ghcr.io/herbiewalker/sanctum:<version>` and `:stable` (moves each release; no `:latest`) with provenance and
  SBOM, and creates the GitHub release. Not yet exercised (no tag pushed).
- `docker-compose.yml` now names the GHCR image (`SANCTUM_IMAGE` / `SANCTUM_VERSION` override);
  `up --build` still builds locally under the same name.

### Added — update notice (2026-11-05, ADR D-19)
- `internal/updatecheck`: opt-in (`SANCTUM_UPDATE_CHECK=true`) daily read-only lookup of the
  GitHub releases API. Raises one Unraid notification per new version and, once logged in,
  shows a banner. It never downloads or applies anything. Dev builds never claim an update;
  redirects, drafts, prereleases and non-github links are refused. 10 tests.
- The running version is now stamped into the binary (`-X main.version`, which previously had no
  variable to land in) and shown in the footer after login and in the startup log.

### Security
- Go toolchain 1.26.7 -> 1.26.10 (`go.mod`, `SETUP.md`) and the Dockerfile builder image re-pinned by
  digest to `golang:1.26-bookworm@sha256:5de7c99e...` (resolved 2026-11-05). govulncheck had found 12
  reachable standard-library vulnerabilities (fixed in 1.26.9), including in `html/template`; it now
  reports 0 affecting the code. The distroless runtime digest is unchanged.

### Fixed
- `sanctum-notify-dispatch.sh` required `python3`, which Unraid does not ship, so every alert since August sat unsent in `pending/`. It now uses `jq` if present, else `sed`, and needs only bash + sed.
- `SANCTUM_LOCKED_ALERT_AFTER_HOURS` / `_DEBOUNCE_HOURS` now accept fractions. Before, a value
  like `0.02` (the documented way to test-fire the alert) made the container fail to start.
- `gofmt` drift from the brand-mark sweep (banner placed before `package` and a misaligned
  const block) that would have failed CI's gofmt gate.

### Added — host-side updater, for source-build installs (2026-11-05)
- (Removed before v0.1.0, see the audit entry above.) `deploy/unraid-scripts/sanctum-update.sh`: fetches release tags from GitHub on the host,
  notifies when a newer stable tag exists, and with `--apply` rebuilds with health-gated
  rollback. Fast-forward-only, optional tag-signature check, `--dry-run` and `--status`.
  The container stays offline and gets no docker socket.

### Fixed
- `sanctum-notify-dispatch.sh` required `python3`, which Unraid does not ship, so every alert since August sat unsent in `pending/`. It now uses `jq` if present, else `sed`, and needs only bash + sed.
- `sanctum-notify-dispatch.sh` split multi-word subjects and bodies apart (whitespace `read`),
  so notifications arrived garbled. Fields now use a non-whitespace separator.

### Added — M6 Phase A (deploy prep, 2026-08-23)
Nothing has hit real hardware yet; the artifacts an operator reads before the first deploy are
the deliverables here.
- `docker-compose.yml` gains the `notify/` bind-mount (writable — Sanctum writes intent files,
  the host script moves them) and every M5 env var (`SANCTUM_NOTIFY_DIR`,
  `SANCTUM_RETENTION_*`, `SANCTUM_VERIFY_EVERY_HOURS`, `SANCTUM_RETENTION_EVERY_HOURS`,
  `SANCTUM_ALERT_EVERY_MINUTES`, `SANCTUM_LOCKED_ALERT_*`, plus
  `SANCTUM_ALLOW_NONTMPFS_TMPDIR=false` for the F01 backstop).
- `.env.example` clarifies `SANCTUM_NOTIFY_PATH` is the HOST-side bind-mount path;
  `SANCTUM_NOTIFY_DIR` (container-internal) is fixed to `/data/notify` in compose.
- `RUNBOOK.md` rewritten cold-readable: prerequisites, first-time deploy on a fresh host,
  first unlock + owner provisioning, post-reboot checklist, notifications install + test-fire,
  ingest, verify-it-is-working, restore drill (with the "actually load it back into Tryst"
  step spelled out), F12 rebuild-from-blobs, upgrade + rollback, moving Sanctum to a
  different Unraid host, emergency: vault-won't-unlock decision tree
  (`ErrBadPassphrase` / `ErrManifestOutOfBand` / `ErrKDFBelowProductionFloor`), known
  failure modes table (empty pending live-fire).
- CI: new `govulncheck` step on the `go` job — 0 reachable vulnerabilities locally as of
  2026-08-23. Closes audit smoke #4. Compose exposure check learned about
  `SANCTUM_NOTIFY_PATH`.
- **Deploy target:** Sanctum is host-agnostic — same image runs on any Unraid box in the
  fleet with the paths pointed appropriately. The first deploy lands on one host; the RUNBOOK's
  relocation section documents moving between hosts.
- Live boot on Unraid is Phase B/C of M6.

### Security — Phase 3 audit remediation (2026-08-23)

Pre-M6 crypto + secrets/storage/logging audit surfaced seven findings across
`internal/vaultkey`, `internal/index/seal.go`, `internal/vault`,
`internal/ingest`, and `internal/httpapi`. All applied and verified before
this entry lands. See [docs/AUDIT.md](docs/AUDIT.md) for the full pass log
(Pass 001 crypto, Pass 002 delta-audit, Passes 003–007 dependencies /
network / injection / build / a11y). Final verdict: **GO** for M6.

- **F01 — TmpDir tmpfs guard.** `vault.Paths.AllowNonTmpfsTmpDir` opt-in
  added; `Vault.New` now requires `TmpDir`, refuses `TmpDir == VaultDir`,
  and on Linux `statfs()`es the path — rejects anything other than
  `tmpfs`/`ramfs` magic unless the opt-in is set. Silent `os.TempDir()`
  fallbacks in `Vault.New` and `ingest.New` removed. Plumbed as
  `SANCTUM_ALLOW_NONTMPFS_TMPDIR` (default false). Runtime backstop for
  hard constraint 2.
- **F02 — Upload body cap.** `/upload` now wraps `r.Body` in
  `http.MaxBytesReader(w, r.Body, MaxBackupBytes+64KiB)` before
  `ParseMultipartForm(16 MiB)`. Previously the parser accepted up to
  1 GiB in RAM — 2× the container memory limit and a straight OOM-kill
  lever. Body-too-large now returns 413 via `isBodyTooLarge` covering
  `*http.MaxBytesError` and the stdlib's wrapped-string form.
- **F03 — Production Argon2id floor.** New `vaultkey.ValidateProduction`
  with `MinProductionTime=3`, `MinProductionMemoryKiB=65536`,
  `MinProductionParallel=1`. Called from `Vault.Unlock` before `Derive`;
  a below-floor manifest returns `ErrKDFBelowProductionFloor` and never
  touches the passphrase. Escape hatch `vault.Options.AllowInsecureKDF`
  is test-only.
- **F04 — Login timing-side-channel.** Login handler now runs the same
  three operations (DB fetch → PBKDF2 → `ConstantTimeCompare`) in the
  same order on both hit and miss paths, substituting a
  `sentinelOwnerAuth()` on the miss path so PBKDF2 and the compare
  execute identically. `ownerLoginIters` promoted to a shared constant.
  Collaterally closes **F06** (removed the mis-labelled
  `"dummy-salt-16bytes!"` literal).
- **F05 — Manifest-binding for seals.** Seal wire format bumped to **v2**
  (52-byte header with `bindHash(32)` after `reserved`, before `nonce`).
  `SealBytes`/`UnsealBytes`/`SealFile`/`UnsealFile` all take a new
  `binding []byte` parameter; SHA-256 is checked BEFORE the AEAD attempt
  via `subtle.ConstantTimeCompare` and also bound into GCM AAD.
  `ErrSealManifestOutOfBand` + top-level `ErrManifestOutOfBand` give the
  operator a distinct signal from "wrong passphrase". `.prev` fallback
  short-circuits on manifest-out-of-band. New
  `internal/vault/binding.go` produces a deterministic hand-rolled
  encoding of the KDF stanza (versioned prefix `SNBIND-01`) instead of
  relying on `json.Marshal`'s field-order stability. Sanctum was pre-M6
  with no live seal on the array, so no migration path was needed —
  v1 seals are rejected outright.
- **F07 — `Key.Bytes()` copies.** `vaultkey.Key.Bytes()` now returns a
  fresh 32-byte copy; the pre-F07 aliasing behaviour is preserved as
  `BytesUnsafe()` for hot paths that need it (none in Sanctum today).
  A caller that stashes the slice past `Zero()` no longer sees silently
  wiped bytes.

### Added
- **M5 — Retention, staleness, alerting.** Four new packages plus a scheduler and a host-side
  User Script.
  - **New ADR D-18** — Unraid notification via a host-watched drop directory. Sanctum writes
    JSON intent files into `${SANCTUM_NOTIFY_DIR}/pending/`; a User Script on the host reads them
    and calls `/usr/local/emhttp/webGui/scripts/notify`. The container never mounts a host binary;
    the host script never reads Sanctum internals. Resolves O-2.
  - `internal/notify`: `Notifier` interface + `FileDropNotifier` (atomic .tmp+rename into the
    drop dir, deterministic per-file counter for stable dispatcher ordering) + `NullNotifier`
    for tests. Intent schema versioned (v1). Body bounded at 4 KiB. Invalid intents rejected
    before any write (severity / kind / subject validation).
  - `internal/retention`: `Policy{KeepMin, MaxAge}` + pure `Decide` (newest is never pruned;
    keep-min and max-age both respected) + `Apply` (delete blob → delete row → log `pruned`
    event; survives a per-backup failure and continues, because a jammed prune is more dangerous
    than a partial one). Dry-run = Decide without Apply.
  - `internal/verify`: F15 full re-verify — a single-pass read that combines the sidecar SHA
    check (fires on `Reader.Close()`) with a trial decrypt against `opened_by_password_id`, then
    falls back to walking the owner's password set the way ingest does. Updates
    `verify_status` + `verified_at`; emits neutral `verify_failed` events. Statuses:
    `ok`, `hash_mismatch`, `decrypt_failed`, `password_absent`.
  - `internal/scheduler`: one ticker, three independent cadences (verify, retention, alerts).
    Skips index-touching work while locked; the alert path runs in BOTH states.
  - `blobstore.Delete` — the ONLY sanctioned deletion path, called exclusively by retention.
    Sidecar-first removal; idempotent on ENOENT.
  - `vault/state.json` — cleartext operational state (`locked_since`, `last_locked_alert_at`)
    written by `vault.Lock`/`Unlock`. Read by the scheduler while LOCKED (D-18) so the
    "locked since X" alert never touches the sealed index.
  - Locked-since alert (R5) fires while locked, reporting only the timestamp — no owner names,
    no counts, no index reads possible. Debounced via `state.json` so a restart cannot re-fire.
  - Staleness alert (F9) per owner — global `SANCTUM_STALENESS_DAYS` default with per-owner
    `owner.staleness_days` override; newest-backup age from `IngestedAt` OR from
    `owner.created_at` when no backups exist yet.
  - `deploy/unraid-scripts/sanctum-notify-dispatch.sh` — the host-side User Script. Reads
    `pending/*.json`, calls Unraid's notify helper, moves files to `sent/` or `failed/`.
    Documented in RUNBOOK with install + test-fire instructions (principle 12 — the notification
    path is not a real path until it has fired).
  - `cmd/sanctum` wiring: notifier constructed from `SANCTUM_NOTIFY_DIR` (NullNotifier if unset);
    scheduler runs on a goroutine that ends on the shutdown context.
  - Config additions: retention (keep-min + max-age-days), all four cadences, locked-alert
    threshold + debounce. Home-lab defaults (verify weekly, retention daily, alerts hourly,
    locked-alert after 24 h).
  - Docs same-change (principle 3): DECISIONS (D-18), DATA_MODEL (`state.json` + notify dirs),
    THREAT_MODEL (R5 revised for the locked-since path + new R7 on channel silence), ROADMAP
    (M5 boxes ticked), RUNBOOK (notifications section).
  - **17 new tests across notify + retention + verify + scheduler.** Every exit criterion forced
    to fire: newest-always-kept, keep-min composition with max-age, empty policy prunes nothing;
    verify hash-mismatch (sidecar rewrite), decrypt-failed (mutated password), password-absent,
    fallback-walk-updates-`opened_by`; locked-since fires past threshold + suppressed inside
    debounce + re-fires after; scheduler pruned-notification fires; verify_failed notification
    fires. `state.json` persistence checked on disk.
  - **Live-fire on Unraid still owed** — the "notification path that has never fired is not a
    notification path" line closes at M6 when the dispatcher lands on the box. Deliberate M5→M6
    handoff (matches ROADMAP's original wording).

- Phase 0 kickoff per the DevPlaybook (checklist 00): repo stand-up, hard constraints, size class
  **L · app-service**, `docker-service` adapter.
- Design docs seeded: `REQUIREMENTS`, `ARCHITECTURE`, `THREAT_MODEL`, `DATA_MODEL`, `ROADMAP`, and
  `DECISIONS` (ADRs **D-1…D-12**, open questions **O-1…O-5**).
- M0 scaffold: Go module, `config` loaded from the environment with no secrets, `/healthz` served
  while LOCKED, graceful-shutdown wiring, tests for the config guards and for `/healthz` not leaking
  configuration.
- `Dockerfile` — multi-stage, distroless, non-root (65532), both base images **pinned by digest**.
- `docker-compose.yml` + `.env.example` — read-only rootfs, `cap_drop: ALL`, `no-new-privileges`,
  tmpfs for all transient state, inbox mounted read-only, resource limits, single bound port.
- `scripts/guards.sh` — the constraint guards as one executable source, called by the `Makefile`,
  `bootstrap.ps1`, and CI alike so they cannot drift.
- `.github/workflows/ci.yml` — gofmt, vet, build, `go test -race`, guards; plus an image job
  asserting non-root, digest pinning, compose exposure/limits, and a trivy vuln+secret scan.
- `bootstrap.ps1` — one-command path from a clean checkout to a green build on Windows.

- **M4 — Lock/unlock + HTTP surface.** Sanctum is now a usable service.
  - `internal/vault`: top-level coordinator + `manifest.json` (Argon2id params cleartext per
    DATA_MODEL — no secrets). Boots LOCKED. `Unlock(passphrase)` derives the runtime key, unseals
    (or creates fresh on first-run), wires ingest + sessions. `Lock()` re-seals, zeros the key,
    clears sessions (N17). Round-trip test proves data survives Unlock→Lock→Unlock cycles.
  - `internal/session`: RAM-only sessions (stronger than tmpfs), 32-byte base64url ids, rolling
    30-min IDLE + 12-hour ABSOLUTE TTLs. `Clear()` invalidates every issued cookie in one call.
  - **New ADR D-17**: session TTLs + RAM-only storage + `Secure`-cookie-only-on-TLS carve-out.
    Resolves O-6.
  - `internal/httpapi` rewritten. All routes: `GET /healthz` · `GET /` · `POST /unlock` (rate-
    limited, N16) · `POST /login` + `POST /provision` (rate-limited) · `POST /logout` · `POST /lock`
    · `GET /status` (F14) · `POST /upload` (F2) · `GET /restore/{id}` (F10, byte-identical +
    `X-Sanctum-SHA256` header) · `GET/POST /passwords` + `POST /passwords/{id}/delete` (F17).
    Server-rendered HTML via `html/template` + `embed`, one page per view, no JS.
  - Cookie flags: `HttpOnly` always, `SameSite=Strict` always, `Secure` only when the request
    arrived over TLS (D-17's honest concession to LAN-only HTTP).
  - Owner-login credentials verified with `subtle.ConstantTimeCompare`; unknown-user path does a
    dummy PBKDF2 to defeat the "no such user" timing side channel.
  - Simple per-IP token bucket for `/unlock` (cap 5, refill 1/min) and `/login` (cap 10, refill
    1/20 s). N16 test forces the burst and asserts the "Too many attempts" page.
  - `cmd/sanctum` real wiring: config → vault → HTTP server; signal context set BEFORE the
    listener (SIGTERM during startup honoured); shutdown = drain HTTP + `vault.Close()` which
    Locks if still unlocked (re-seal + zero key + reset). N11 wired.
  - **`sanctum -healthcheck` flag** — closes the M0 gap. Probes `/healthz` on localhost, exits
    0/1. Verified live.
  - **Live server end-to-end run today**: unlock → provision → `/lock` writes `index.sealed` to
    disk; subsequent wrong-pw unlock fails cleanly; correct-pw unlock re-loads the seal and
    serves. The seal path SIGTERM would trigger is proven; only signal delivery itself remains
    unverifiable on Windows (OL-7 stays open until a real `docker stop` on the Unraid host).
  - Fixed a latent bug from M2's `UnsealFile`: when the primary seal fails auth AND `.prev`
    doesn't exist (first-run vault), it now returns the auth error rather than "file not found".
  - New tests: 11 session, 10 vault, 9 httpapi (real vault + httptest). Every M4 exit criterion
    forced to fire — including N17 (session cookie issued pre-relock rejected post-relock),
    N8 (byte-identical restore verified by `bytes.Equal(orig, restored)`), N16 (rate limit trips
    on the 5th attempt), F11 (`/status` while locked → 303 to `/`).
- **M3 — the ingest pipeline.** Two new packages plus the newly-armed guard:
  - `internal/ingest`: the single pipeline every backup takes to get into the vault.
    `Service.IngestReader(ownerID, source, filename, r)` and `IngestFile(ownerID, path)`. Order
    matters and is deliberate: LOCKED-check first (D-4 defence-in-depth, `atomic.Bool`) → stage
    to tmpfs while hashing (bounded by `MaxBackupBytes` with a one-byte overflow probe) → cheap
    header probe → **F13 duplicate check by SHA before any KDF work** → walk D-13 password set
    in `last_used_at DESC` order → first opener wins → `blobstore.Put` → single-transaction
    insert of `backup` row + all `backup_table_count` rows + `owner_backup_password.last_used_at`
    bump + neutral `ingest_ok` event. Every failure path unlinks the tmpfs stage via a
    top-of-function `defer os.Remove`. A rare tx failure after a successful blob-store Put
    logs a prominent "orphan blob" warning with SHA + path so a future reconciliation catches it.
  - `internal/watcher`: poll-based inbox watch (no fsnotify dependency — home-lab cadence
    doesn't earn it). Default 5 s poll + 2 s stability window. Ignores non-`.tryst` and hidden
    files; a rejected file is not retried (operator moves/renames); disappearing files pruned
    from tracking; `context.Cancel` stops Run cleanly. Takes an `Ingester` interface so it can
    be unit-tested without a real service.
  - **`guard-no-plaintext` armed.** `scripts/guards.sh no-plaintext` runs
    `TestGuard_NoPlaintextAfterIngest`, which builds a synthetic backup whose `data.json`
    carries a sentinel string, ingests it, then walks the vault dir asserting no file contains
    the sentinel, the ZIP magic `PK\x03\x04`, or a JSON-open prefix. **Forced to fail** during
    development by injecting a plaintext-write into the pipeline: the guard caught it on both
    the sentinel and JSON-open checks. Principle 12 satisfied — the safety mechanism has fired
    for real.
- 19 new test cases (ingest 13, watcher 6). Every T6 rejection shape forced: wrong password,
  flipped byte, bad header, absurd iteration count, Zip-Slip, oversize. Locked-vault refusal
  proved (before touching input). Plus a full N15 log-scrape test that plants sentinels in a
  data.json's partner-name/note/password and confirms none leak into slog output OR into any
  `event.detail`.
- **M2 — the storage foundation.** Three new packages:
  - `internal/vaultkey`: Argon2id KDF (new **ADR D-16**) with a `Key` struct that panics on
    use-after-`Zero()`. Production and insecure-for-test parameter profiles, with
    `IsInsecureForTest()` so a misconfigured deployment cannot silently ship the fast profile.
  - `internal/blobstore`: immutable, owner-scoped storage for `.tryst` blobs. Atomic writes
    (`.tmp` → rename), a SHA-256 sidecar per blob, streaming verify-on-read (`ErrHashMismatch`
    fires the moment tampered bytes cross the reader). Rejects duplicate ids and any id that
    could escape its owner dir.
  - `internal/index`: SQLite schema v1 via **`modernc.org/sqlite`** (pure Go — cgo-free, D-5
    holds). Schema matches DATA_MODEL exactly, including the `owner.login_*` columns (D-14),
    the `owner_backup_password` table (D-13), `backup.opened_by_password_id`, and the reserved
    `__media__` synthetic row in `backup_table_count` (D-15). Idempotent forward-only
    migration harness runs on `Open`.
- **Seal / unseal** (`internal/index/seal.go`): `SNSL` v1 wire format — 4-byte magic + version
  + 12-byte GCM nonce + AEAD ciphertext. Header bytes bound into the AAD. `SealFile` promotes
  the current seal to `.prev` atomically, `UnsealFile` falls back to `.prev` on primary auth
  failure. Wrong key returns `ErrSealAuth` cleanly; both flipped-byte and wrong-key tampering
  are forced-fail tested (principle 12).
- **Serialize + LoadInto**: the in-memory index round-trips via `VACUUM INTO` on a tmpfs path
  → seal → unseal → LoadInto. Never writes plaintext SQLite bytes to the array.
- **Rebuild-from-blobs** (F12): reconstructs `backup` + `backup_table_count` from a blob store
  using a supplied candidate password set. Placeholder `owner` rows are materialised with
  random unusable login credentials — deliberate: the operator must re-provision credentials
  and the password set through the explicit flow rather than inherit a placeholder identity.
  A populated vault with no candidate passwords returns `ErrRebuildNoPasswords` rather than
  silently reporting zero recovery. Tampered blobs are counted skipped, not silently accepted.
- **CGO_ENABLED=0 still builds the static binary** — modernc.org/sqlite is pure Go, so D-5's
  distroless-image story is intact.
- Every M2 negative case forced to fire: `Put` duplicate → `ErrBlobExists`, on-disk tampering
  → `ErrHashMismatch`, missing sidecar → error surfaced (not hidden), invalid id → rejected,
  wrong seal key → `ErrSealAuth`, corrupted seal → `ErrSealAuth` with `.prev` fallback,
  rebuild against tampered blob → `BlobsSkipped++` (no partial-truth landing), rebuild against
  no-matching-password blob → `BlobsUnopenable++`.
- New **ADR D-16**: vault-unlock KDF is Argon2id (production `t=3, m=64 MiB, p=4`) distinct
  from owner-login PBKDF2 (D-14) — two different threat models, two different KDFs.
- **M1 — the `TRYSTBK1` reader.** `internal/trystbk` now opens real Tryst backup files end-to-end.
  Header (`header.go`) parses magic/version/salt/iterations with the 100k–5M attacker bound.
  Body reader (`reader.go`) derives PBKDF2, wraps in `tink-go`'s `AesGcmHkdfStreaming`, and
  decrypts into a bounded `bytes.Buffer` (512 MiB cap + one-byte overflow probe). ZIP inspector
  (`zip.go`) walks the central directory with Zip-Slip validation on every name, streams
  `data.json` row counts via `json.Decoder` (encounter rows never materialise), and counts media
  entries from the central directory only (D-15 / N19) — proven by a synthetic entry with
  compression method 99 whose `Open()` fails, so the fact that `inspectZip` succeeds is the proof
  we never opened it.
- **Interop verified against three real fixtures** (2026-08-22): 3 KB catalog-seed (schema v15,
  6 tables), 21 MB (schema v8, 6 media entries, 22 MB media), 34 MB multi-segment (schema v8,
  11 tables, 14 media, 34 MB media). **Residual risk R6 closed; OPEN_LOOPS OL-8 closed.**
- Every M1 negative test is **forced to fire** (principle 12): wrong password on both synthetic
  and real fixtures, single-bit flip mid-stream, header truncation across five lengths, five
  out-of-bounds iteration counts, five Zip-Slip attack shapes, malformed ZIP, missing data.json.
- **D-13, D-14, D-15** — the three ADRs M1 could not proceed without, resolved rather than
  deferred: per-owner backup-password **set** sealed with the encrypted index, so unattended ingest
  can trial-decrypt across Tryst password rotations (closes O-1); split **vault-unlock + owner
  login** from day 1, collapsed to one screen for the solo v1 user so no auth retrofit is needed
  when a second owner arrives (closes O-3); **media counted from the ZIP central directory only**,
  never extracted, with a reserved `__media__` synthetic row in `backup_table_count` (closes O-4).
  Threaded through `DATA_MODEL` (new `owner_backup_password` table, new `owner.login_*` columns,
  new `backup.opened_by_password_id` column), `REQUIREMENTS` (F16–F19, N16–N19), `ARCHITECTURE`,
  `ROADMAP`, and `THREAT_MODEL`. Three open questions remain: O-2 (Unraid notification transport,
  M5), O-5 (browser-side decryption, v2), O-6 (session TTL, M4).
- `internal/trystbk` — the `TRYSTBK1` container format transcribed as constants from Tryst's
  `EXPORT_FORMAT.md`, with tests that **validate ADR D-6 before M1 builds on it**: `tink-go`'s
  `streamingaead/subtle.NewAESGCMHKDF` does accept raw PBKDF2 output with no keyset, and round-trips
  across multiple segments. Flipped byte, wrong associated data, and wrong password are each forced
  to fail (principle 12), the last asserting zero partial output (N7).

### Verified
> What has actually been run, as opposed to reviewed (principle 11).

- **Clean-checkout build** — cloned to a fresh directory: build, vet, test, guards, and the binary
  serves `/healthz` reporting `locked`.
- **Every guard forced to fail** before being trusted: digest stripped from a `FROM`, `.env`
  tracked, `.tryst` tracked, credential hardcoded. All four tripped; all four recovered.
- **First green CI run** (2026-08-22) — both jobs. The image job **built the container for the
  first time** and asserted non-root (`65532:65532`), digest pinning, compose exposure and limits,
  and a clean trivy vuln+secret scan.
- 13 real `TRYSTBK1` v1 fixtures confirmed present for the M1 interop test, 3 KB to 34 MB.

### Known gaps
> Recorded rather than implied. Principle 11: a green build is a low rung on the ladder.

- **Tested on one host only** (one Unraid server, one user's data). The live smoke checks
  (`scripts/smoke-live.sh`: tmpfs refusal, oversize upload, tampered manifest, KDF floor, kill-and-restart)
  all passed there on 2026-11-11; nobody else has run it.
- **No independent security review.** Eight self-run audit passes, not an external one.
- **The smoke script's memory sampler read 0 MiB** on that host, so "memory stays flat" during the
  oversize upload is inferred from the instant 413, not measured (D15, to fix in a patch release).
- Audit nits D10 to D14 are open for a patch release (see `docs/AUDIT.md`).
- Plain HTTP, LAN only (D-12). Go may keep copies of the runtime key in memory after it is zeroed.
- An unattended reboot leaves the vault locked and not ingesting; the staleness alert is what catches it.
