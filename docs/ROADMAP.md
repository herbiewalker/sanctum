# Sanctum — Roadmap

> **Status:** M0 in progress (2026-08-22). Milestones in order; **foundations before features**
> (principle 2). Each milestone has exit criteria and is not done until they are met
> (`checklists/01-milestone-exit.md`). Do not start the next until the current one exits.

The sequencing rule that shaped this list: **crypto and key handling come before storage, storage
comes before ingest, ingest comes before anything scheduled, and the UI comes last.** You cannot
retrofit encryption onto plaintext blobs, and a vault that ingests before it can verify is just a
folder.

---

## M0 — Scaffold & CI gates *(no features)*

- [x] `git init`, commit identity, LICENSE (MIT, D-7), `.gitignore`, `.gitattributes`, `.editorconfig`
- [x] `CLAUDE.md` with hard constraints + size class; `README.md` with an honest Status line
- [x] `SETUP.md` with the toolchain pin and the platform traps
- [x] Design docs seeded: REQUIREMENTS, ARCHITECTURE, THREAT_MODEL, DATA_MODEL, DECISIONS, this file
- [x] Go module + a scaffold binary that serves `/healthz`, handles SIGTERM, and builds green
- [x] `Dockerfile` — multi-stage, distroless, **both bases pinned by digest**, non-root
- [x] `docker-compose.yml` + `.env.example` — read-only rootfs, `cap_drop: ALL`, tmpfs mount,
      resource limits, single published port
- [x] CI green: `go build`, `go vet`, `gofmt -l`, `go test -race ./...` — first green run
      2026-08-22
- [x] **Constraint guards wired and forced to fail before being trusted** (principle 12) — each of
      digest-pin, `.env`-tracked, `.tryst`-tracked and hardcoded-credential was deliberately
      tripped, then restored. Image job asserts non-root (`65532:65532`), digest pinning, compose
      exposure/limits, and a clean trivy vuln+secret scan
- [x] Clean-checkout verification: cloned to a fresh directory, built, tested, guards ran, binary
      serves `/healthz` reporting `locked`
- [ ] **Healthcheck flag** — `docker-compose.yml` calls `sanctum -healthcheck`, which does not exist
      yet. Distroless has no shell or curl, so this cannot be a `curl -f`
- [ ] **Verify graceful shutdown** — `docker stop` must log `shutdown complete` (N11). Unverifiable
      on Windows: Git Bash cannot deliver a real SIGTERM to a native binary, so it terminates at
      exit 143 without running the handler. Tracked as OL-7
- **Exit:** a clean checkout reaches a green build and a green CI run with every guard armed;
  the image runs as non-root and serves `/healthz`. **No user data has been touched yet.**
  *(Two boxes remain: the healthcheck flag and the SIGTERM verification.)*

## M1 — Crypto foundation: read `TRYSTBK1`

> The highest-risk milestone in the project. Everything downstream trusts this code.

**Groundwork done (2026-08-22):** `internal/trystbk/format.go` transcribes the container spec as
constants, and `format_test.go` **validates ADR D-6 before anything is built on it** —
`streamingaead/subtle.NewAESGCMHKDF` does accept raw PBKDF2 output with no Tink keyset, and
round-trips across multiple segments. Three negative cases are forced to fail: flipped byte, wrong
associated data, wrong password (with zero partial output, N7). This proves the *primitive*, not
wire-compatibility with the app.

**Fixtures confirmed available:** 13 real `TRYSTBK1` v1 backups in a private local folder,
from 3 KB (fast tests) to 34 MB (real multi-segment streaming). They are **real user data** — hard
constraint 4 means they are never committed; the interop test reads a path from an env var and
skips when unset.

- [x] `internal/trystbk/header.go` — parse (magic, version, salt, iterations with the 100k–5M
      bound); every out-of-bounds and truncation case tested
- [x] PBKDF2-HMAC-SHA256 key derivation via `golang.org/x/crypto/pbkdf2`, matching Tryst's params
- [x] `tink-go` `AesGcmHkdfStreaming` reader — 1 MiB segments, AD `tryst-backup-v1`, decrypted body
      bounded by `MaxBackupBytes` (512 MiB) with a one-byte overflow probe
- [x] ZIP walk with Zip-Slip validation on every entry name (N10) — 5 attack shapes rejected,
      5 benign shapes allowed
- [x] Generic `data.json` read → `schemaVersion` + per-table row counts, **counts only** (D-15);
      streamed with `json.Decoder`, encounter rows never materialised
- [x] Media entries counted from the ZIP central directory only — N19 proven with a synthetic
      method-99 entry whose Open() fails, and inspectZip succeeding means we never opened it
- [ ] `internal/vaultkey`: passphrase → runtime key, RAM-only, zeroed on lock/SIGTERM
      *(deferred to M2 — it belongs with the sealed-index code that uses it)*
- **Exit:**
  - [x] **Interop against genuine `.tryst` files** — passed 2026-08-22 against three real fixtures:
        3 KB catalog-seed (schema v15, 6 tables), 21 MB (schema v8, 6 media, 22 MB media), 34 MB
        multi-segment (schema v8, 11 tables, 14 media, 34 MB media). **Residual risk R6 closed;
        OL-8 closed.**
  - [x] Negative tests all **forced to fire** (principle 12): wrong password (N7, both synthetic
        and against the real fixture), flipped byte (N6), header truncation, absurd iteration count
        (N9, five variants), Zip-Slip names (N10, five shapes), malformed ZIP, missing data.json.
  - [x] No plaintext written outside memory during any test — the reader path only ever holds
        decrypted bytes in a `bytes.Buffer` that goes out of scope on return (N1's spirit; the
        guard proper still reports SKIP because M3 is what installs an ingest path to attack).

## M2 — Storage foundation: blob store + sealed index

- [x] `internal/blobstore`: immutable, owner-scoped writes; SHA-256 manifest; verify-on-read (D-11).
      Duplicate-put returns `ErrBlobExists`; tampering detected via `Verify()` and via the
      streaming `Reader` on Close.
- [x] `internal/index`: SQLite schema v1 per `DATA_MODEL.md`, via **`modernc.org/sqlite`** (pure
      Go — cgo-free, per D-5/D-6). Includes the `owner` login columns (D-14), the
      `owner_backup_password` table (D-13), `backup.opened_by_password_id`, and the reserved
      `__media__` synthetic row support (D-15). Foreign keys enforced.
- [x] **New ADR D-16**: vault-unlock KDF is Argon2id (production `t=3, m=64 MiB, p=4`) —
      distinct from owner-login PBKDF2 (D-14) because it defends against a different threat.
      `internal/vaultkey` implements it with a `Zero()`-able runtime key struct and a
      `TestParams()` mode marked insecure-for-test.
- [x] Seal/unseal the index as an AES-256-GCM blob (`SNSL` v1) keyed by the runtime key;
      `index.sealed.prev` kept one generation, promotion is atomic (`.tmp` → rename), unseal
      falls back to `.prev` if the primary fails auth.
- [x] Serialize the in-memory index via `VACUUM INTO` on a tmpfs path; `LoadInto` restores it into
      a fresh index on tmpfs. Never writes plaintext SQLite bytes to the array.
- [x] **Rebuild-index-from-blobs** (F12) — the D-5 recovery path. Recovers `backup` +
      `backup_table_count` (with `__media__`); each recovered owner is materialised as a
      placeholder row with random unusable login credentials, forcing the operator to
      re-provision credentials and the D-13 password set through the explicit flow. Documented
      in `RUNBOOK.md`.
- [x] Migration harness (`migrations.go`) — idempotent, forward-only, one migrator per schema
      version; runs on every `Open`.
- **Exit:**
  - [x] Blobs survive a "container restart" (Put → new Store → Get + Verify passes; tampering
        detected forcibly).
  - [x] Wrong passphrase → `ErrSealAuth` cleanly, no partial output.
  - [x] Round-trip: OpenInMemory + insert + Serialize + Seal + Unseal + LoadInto → identical
        rows and table_counts.
  - [x] Rebuild-from-blobs recovers the intended subset from synthetic vaults; a vault with
        blobs but no candidate passwords returns `ErrRebuildNoPasswords` (not silent
        zero-recovery); tampered blobs are counted skipped, not silently accepted.
  - [x] `CGO_ENABLED=0 go build` still produces the static binary — the pure-Go SQLite driver
        does not compromise the distroless image.
  - [ ] `guard-no-plaintext` still SKIPs at the whole-project level (M3 is what installs the
        real ingest path). The blobstore-side check is already inline
        (`TestPut_LeavesNoZipMagicOnDisk`).

## M3 — The ingest pipeline

- [x] `internal/ingest`: LOCKED-check → stage to tmpfs (hash while copying, bounded by
      `MaxBackupBytes` + overflow probe) → cheap header probe → **F13 duplicate check by SHA
      before any KDF work** → walk D-13 password set in `last_used_at DESC` order → first opener
      wins → `blobstore.Put` → single-transaction insert of `backup` + `backup_table_count` +
      `owner_backup_password.last_used_at` bump + `ingest_ok` event.
- [x] Blob move is the last irreversible step; every failure path unlinks the tmpfs staging file
      via a top-of-function `defer os.Remove`, so no plaintext residue survives a rejection.
- [x] Duplicate detection by SHA-256 (F13) — checked at the index BEFORE KDF work, and again at
      the blob-store level (`ErrBlobExists` → `ErrDuplicate`) as a race guard.
- [x] `internal/watcher`: poll-based inbox watch with a stability window (default 2 s over a 5 s
      poll cadence). Grows-then-stops file waits until stable; non-`.tryst` files ignored; a
      rejected file is not retried (operator moves/renames); a file that disappears mid-poll is
      pruned from tracking.
- [x] Hostile-input handling for every T6 shape, each with a **neutral event row** (`sha=xxx
      reason=...`) — never a password, never encounter content (N15). Forced tests for wrong
      password, flipped byte, bad header, absurd iteration count, Zip-Slip, and oversize input.
- [x] **`guard-no-plaintext` FINALLY ARMED.** `scripts/guards.sh no-plaintext` runs
      `TestGuard_NoPlaintextAfterIngest`: builds a synthetic backup whose data.json carries a
      sentinel string, ingests it, then walks the vault dir asserting no file contains the
      sentinel, the ZIP magic `PK\x03\x04`, or a JSON-open prefix. **Forced to fail** during
      development by injecting a plaintext-write into the pipeline — the guard caught it on
      both the sentinel and JSON-open checks.
- **Exit:**
  - [x] Happy path: `IngestReader` end-to-end returns a `Result`, blob lands in vault (byte
        identical), `backup.opened_by_password_id` populated, `owner_backup_password.last_used_at`
        bumped, tmpfs residue check clean.
  - [x] Locked vault: `Lock()` before Ingest → `ErrVaultLocked` before any input touched;
        `Unlock()` restores; nothing lands anywhere in the locked case (index rows = 0, vault
        entries = 0).
  - [x] T6 rejections: wrong password → `ErrRejected` + `ingest_rejected` event with reason
        `no_password_matched`; flipped byte → same; bad header → reason `bad_header`; absurd
        iterations → reason `bad_header`; Zip-Slip → reason `structural`; oversize input →
        `ErrRejected` at the staging cap with tmpfs cleanup verified.
  - [x] N15 log scrape: full happy-path ingest of a data.json containing partner-name/note/password
        sentinels, then scrape both slog output AND `event.detail` — no sentinel leaked in either.

## M4 — Lock/unlock + HTTP surface

- [x] `internal/vault` coordinator with manifest (Argon2id params persisted as cleartext per
      DATA_MODEL), LOCKED boot state, `Unlock(passphrase) → Lock() → Unlock(same passphrase)`
      round-trip preserves data. Wraps blobstore + index + ingest + session. Wrong-passphrase
      unlock returns `ErrBadPassphrase` cleanly, vault stays locked.
- [x] `internal/session` — RAM-only sessions (stronger than tmpfs; container restart re-locks
      anyway), 32-byte base64url ids, IDLE-rolls + ABSOLUTE-max TTLs (D-17). `Clear()` invalidates
      every issued session; called from `vault.Lock` (N17).
- [x] **`internal/httpapi` rewrite** — all routes: `GET /healthz` (locked-safe), `GET /` (dispatches
      unlock/login/dashboard), `POST /unlock` (rate-limited, N16), `POST /login` +
      `POST /provision` (rate-limited), `POST /logout`, `POST /lock`, `GET /status` (F14),
      `POST /upload` (F2 — wired through `ingest.Service`), `GET /restore/{id}` (F10, byte-identical
      + `X-Sanctum-SHA256` header), `GET/POST /passwords` + `POST /passwords/{id}/delete` (F17).
      Server-rendered HTML via `html/template` + `embed`, one page per view, no JS.
- [x] Cookie flags: `HttpOnly` always, `SameSite=Strict` always, `Secure` **only when the request
      arrived over TLS** — Sanctum is LAN-only (D-12) with no cert, so always-Secure would drop
      the cookie. Recorded as accepted residual in D-17 / THREAT_MODEL.
- [x] **New ADR D-17** — session TTL: 30-minute idle (rolling), 12-hour absolute (not extendable),
      RAM-only. Resolves O-6.
- [x] Owner-login credentials verified with `subtle.ConstantTimeCompare` after PBKDF2 (D-14);
      unknown-user path does a dummy PBKDF2 to avoid a timing side channel between
      "no such user" and "wrong password".
- [x] `cmd/sanctum` — full wiring: config → vault → HTTP server; signal-context set BEFORE the
      listener (any SIGTERM during startup still honoured); shutdown = drain HTTP + `vault.Close()`
      = re-seal + zero the key + reset state (N11).
- [x] **`sanctum -healthcheck` flag** — closes the M0 gap. Probes `/healthz` on localhost, exits
      0/1. What the compose HEALTHCHECK has been calling since M0.
- **Exit:**
  - [x] Byte-identical restore (N8) — synthetic backup uploaded via `/upload`, restored via
        `/restore/{id}`, `bytes.Equal(orig, restored)` and `X-Sanctum-SHA256` header verified.
  - [x] A restart leaves the vault locked. Verified end-to-end via live server: unlock, provision,
        `/lock` → `/healthz` reports `state=locked`, wrong-pw unlock afterwards fails cleanly.
  - [x] Burst of wrong unlock attempts rate-limited (N16) — token bucket, capacity 5, refill
        1/minute; 5th wrong attempt on a bucket that started empty returns the "Too many attempts"
        page.
  - [x] Session cookie issued before a re-lock cycle fails to authenticate afterwards (N17).
  - [ ] SIGTERM handler executes end-to-end on a real Unraid host. Windows can't deliver a real
        SIGTERM (SETUP.md); the `vault.Close()`-triggered seal path IS verified via
        `POST /lock` on the live server (same code path), and CI's Linux build exercises the
        wiring — but a genuine `docker stop` on the box still closes OL-7.

## M5 — Retention, staleness, alerting

- [x] **New ADR D-18** — Unraid notification via a host-watched drop directory. Resolves O-2.
- [x] `internal/notify`: `Notifier` interface, `FileDropNotifier` (atomic .tmp+rename into
      `${SANCTUM_NOTIFY_DIR}/pending`), `NullNotifier` for tests. Intent schema versioned; body
      bounded at 4 KiB; invalid intents rejected before any write (severity/kind/subject validation).
- [x] `internal/retention`: `Policy{KeepMin,MaxAge}`; pure `Decide` (newest is never pruned,
      keep-min + max-age both respected); `Apply` deletes blob → deletes row → logs `pruned`
      event, survives one failure and continues (jammed prune is worse than partial). Dry-run =
      Decide without Apply.
- [x] `internal/verify`: full re-verify of a stored blob — single-pass read that combines the
      sidecar SHA check (on `Reader.Close()`) with a trial decrypt against the recorded
      `opened_by_password_id` and, on decrypt failure, the owner's password set (same walk
      ingest does). Updates `verify_status` + `verified_at`; emits neutral `verify_failed` events.
- [x] `internal/scheduler`: one ticker, three tasks on independent cadences (verify,
      retention, alerts). Skips index-touching work while locked; alert path runs in BOTH states.
- [x] `blobstore.Delete` — the ONLY sanctioned deletion path, called exclusively by retention.
      Sidecar-first removal; idempotent on ENOENT so a retry converges.
- [x] `vault/state.json` — cleartext operational state (`locked_since`, `last_locked_alert_at`)
      written by `vault.Lock`/`Unlock`. Read by the scheduler while LOCKED (D-18) so the
      "locked since X" alert never touches the sealed index. Debounce survives restarts.
- [x] Staleness evaluation per owner (F9) — global default `SANCTUM_STALENESS_DAYS`, per-owner
      override in `owner.staleness_days`, newest-backup age from `IngestedAt` OR from
      `owner.created_at` when no backups exist yet.
- [x] Locked-since alert (R5) fires while LOCKED reporting only the timestamp — no owner names,
      no counts, no index reads needed.
- [x] `deploy/unraid-scripts/sanctum-notify-dispatch.sh` — the host-side User Script that reads
      `pending/*.json`, calls `/usr/local/emhttp/webGui/scripts/notify`, and moves files to
      `sent/` or `failed/`.
- [x] `cmd/sanctum` wiring: notifier constructed from `SANCTUM_NOTIFY_DIR` (NullNotifier if unset);
      scheduler started with a goroutine that ends on the shutdown context.
- [x] Config: retention policy + cadences + locked-alert threshold/debounce, all env-driven with
      home-lab defaults (verify weekly, retention daily, alerts hourly, locked-alert after 24 h).
- [x] Docs updated same-change (principle 3): DATA_MODEL (state.json + notify dirs), THREAT_MODEL
      (R5 revised + new R7 on channel silence), DECISIONS (D-18 added).
- **Exit:**
  - [x] Retention: Decide + Apply forced tests including newest-is-always-kept, keep-min +
        max-age composition, empty-policy prunes-nothing; scheduler drives a real prune of
        two-of-three synthetic backups and fires a `pruned` notification.
  - [x] Verify: happy path, hash-mismatch forced (rewritten sidecar), decrypt-failed forced
        (mutated password), password-absent forced, fallback rescue walking the set updates
        `opened_by_password_id`.
  - [x] Locked-since: fires past `LockedAlertAfter`; suppressed inside debounce; re-fires after
        debounce; quiet while unlocked; `last_locked_alert_at` persisted to `state.json`.
  - [x] Notify: intent files written atomically, ordered by filename, validation rejects
        malformed intents without writing.
  - [x] N15 respected: alert bodies carry owner label + counts + reason codes; never a partner
        name, filename, or event `detail` from the index.
  - [ ] **Live-fire on a real Unraid box** — the "notification path that has never fired is not
        a notification path" line is satisfied when M6 deploys the dispatcher and one intent is
        confirmed on the operator's dashboard. Deliberate M5→M6 handoff.

## M6 — Deploy to Unraid *(the first live rung)*

- [ ] `RUNBOOK.md` complete: start/stop, unlock, post-reboot checklist, backup, restore, rollback
- [ ] Deployed on the real box, LAN-only, non-root, limits applied
- [ ] **Validation ladder** (principle 11): synthetic fixture → one real backup → the full history
- [ ] Restore drill: restore a backup out of Sanctum and **actually import it into Tryst**
- **Exit:** the README's "never yet run on a live target" status line comes off — and not before
  (principle 11 / lesson L14). A restore has been proven by loading it back into the app, not by
  comparing hashes alone.

---

## Post-M6 candidates *(captured 2026-08-23 — order set at next planning session)*

> Feature freeze applies (principle 9): nothing here starts until M6 exits and its retro is written.
> These are backlog placeholders — the shape of each milestone lands when it moves to the top.

### One-command deploy on any Unraid host
> "Copy one line in the terminal and deploy — no SSH, no key, no build wait."

The current workflow needs: SSH into the box, mint a deploy key, add to GitHub, `git clone`,
`docker build`, then Compose Manager. That is too many steps for the goal of
"drop Sanctum onto any of my servers whenever I want."

Two paths, not mutually exclusive:

- **A — Publish image + go public.** Publish `sanctum` to GHCR as a public image (per-tag digest
  pinned), make the repo public (walks `/pb-going-public` first — full git-history secret/PII
  audit, README-for-strangers, license clarity). The compose file loses its `build:` stanza; the
  operator pastes a compose file + env, Compose Up, done.
- **B — Unraid Community App template.** Author a template XML in `dcflachs`'s templates repo so
  Sanctum appears in the Community Applications tab of every Unraid box. One click install with
  all fields exposed as GUI form inputs. Depends on Path A being done first (needs a public image).

### Mobile-friendly, modern UI
> "Sanctum has to work on the phone browser cleanly — Tryst is a phone app, the daily-driver
> restore flow is a phone flow."

Present state: server-rendered semantic HTML, functional but desktop-centric layout, minimal
styling. Audit U01/U02/U03 flagged low contrast on hint text, weak focus indicators, and
error-severity conveyed by color only.

Scope this milestone as a bundle:

- Responsive layout that works cleanly on 375 px-wide phone viewports without horizontal scroll.
- Design system: type scale, spacing tokens, focus states, dark-mode polish (currently just
  `color-scheme: light dark`, no polish beyond browser default).
- WCAG AA contrast, keyboard-first operability, aria-live on error boxes.
- The restore flow specifically works one-handed on a phone (large tap targets, no hover-only
  affordances).

### Ongoing backlog
> Add items here as they surface. This list is expected to grow.

- **Upload and download progress visuals** *(user request, 2026-11-06).* Found live: a 419 MB upload
  shows a frozen page for minutes (transfer, then trial decrypt: 600k PBKDF2 rounds per saved password,
  tried in turn), so it looks hung. Show where the user is in the process:
  - Upload: a real transfer progress bar (XHR/fetch with upload progress events, small inline script,
    page must still work with scripting off), then clearly named server-side stages ("Uploaded", "Checking
    the header", "Trying saved passwords (2 of 3)", "Opening the archive", "Stored") instead of one spinner.
    Server side that likely means the upload returns at once with a job id and the page polls a small
    status endpoint, which also survives a browser tab being closed mid-verify.
  - Download (restore): show size and progress while streaming; set `Content-Length` so the browser's own
    progress bar is accurate, and say "preparing" while the blob is verified before the first byte.
  - Same pass should cover a hard size/limit message up front (the 512 MiB format cap) so a too-large file
    fails before the transfer, not after.
  Fits naturally with the mobile UI bundle above; keep the no-JS fallback and the CSP unchanged (no inline
  script: ship it as a same-origin file).

---

## Pre-release audit (Phase 3)

> A separate program, not a feature milestone. Freeze features first (principle 9); one lens per
> **fresh session** (`/pb-audit-pass`). See `checklists/02-pre-release-audit.md`.

- [ ] Dependencies & licenses (Go module graph; confirm no GPL contamination per D-7)
- [ ] Secrets / storage / logging (N2, N15 — the highest-value lens here)
- [ ] Network / exposed surface (D-12; confirm only the one port, no host network)
- [ ] Input / injection (the whole of T6 — the inbox is untrusted input)
- [ ] Build hardening (non-root, read-only rootfs, caps, digest pin, trivy clean)
- [ ] Crypto review — a dedicated lens, given D-6 chose a different implementation from the app's
- [ ] **Go / no-go**, listing covered vs accepted residual (`THREAT_MODEL.md` R1–R6)

## Deferred / backlog

| Item | Why deferred | Gate |
|------|--------------|------|
| Viewing own encounter data | v1 is a vault (D-15 counts media, does not extract) | v2 |
| Partner sharing / aggregate view | Needs its own ADR **and** a full `THREAT_MODEL` revision — a second owner changes every row | D-9, D-14 |
| Browser-side decryption | The better long-term answer to R2, and real work | O-5 |
| Sidecar Android app for push-button sync | Deferred, not rejected — Syncthing solves the transport today | D-1 |
| Remote access | Tailscale/WireGuard only, never an exposed port | D-12 |
| Second owner provisioning | Schema and auth split support it from day 1 (D-8, D-14); the flow is not built | O-6 |
