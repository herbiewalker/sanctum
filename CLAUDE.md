# Sanctum — Project Context for Claude Code

> A self-hosted, locked-by-default vault that ingests, verifies, and retains encrypted **Tryst**
> backups on Unraid — and, later, gives two partners an opt-in shared view of their own data.

Project name **Sanctum**, Go module **`github.com/herbiewalker/sanctum`**, container **`sanctum`**.
**Size class:** **L · app-service** — per the DevPlaybook sizing matrix. Network service + the most
sensitive data category the owner holds + persistent state + cryptography. Full doc suite,
`THREAT_MODEL` and `DATA_MODEL` included, all checklists at full weight. Adapter:
`docker-service` (the author's private playbook).

Companion to **[Tryst](https://github.com/herbiewalker/tryst)** — a privacy-first, local-only
Android intimacy tracker on F-Droid. Sanctum consumes Tryst's `TRYSTBK1` backup container. Read
[`tryst/docs/EXPORT_FORMAT.md`](../tryst/docs/EXPORT_FORMAT.md) before touching any crypto here.

## Brand mark — intentionally not wired here

The author's herbiewalker code brand (`⏣` sigil; source lives in a private playbook)
is **skipped** in this repo's current bash surface:
- `deploy/unraid-scripts/sanctum-notify-dispatch.sh` — silent cron dispatcher; a banner would spam logs every 2 minutes.
- `scripts/guards.sh` — CI/dev guard runner; identity banner has no place in CI output.

If sanctum grows a user-facing shell entrypoint later (e.g. a `sanctum unlock`
CLI wrapper), use the pattern from `unraid-scripts/hardware-stress-test`:
inline the ~15-line self-contained `brand_banner_modern` block and call it
at startup. For silent operations that still want the mark, prefix log/notify
subjects with `⏣` (see `unraid-scripts/nvidia-healthcheck` for the pattern).

The Go binary itself has no brand mark yet. When it grows a startup log line,
port the palette + `⏣` sigil to Go and use it there — brand.sh is the
reference, not the requirement.

---

## Hard constraints (these OVERRIDE default behavior — do not violate)

> If a request conflicts with one of these, **say so and propose an alternative** — do not quietly
> comply. Each one that can be a CI check **is** one (principle 1).

1. **Tryst is never modified.** Sanctum requires **zero changes** to the Tryst app. Tryst's
   `checkNoNetworkRelease` gate, its `D-1` (no accounts/sync/second device), `D-2` (protects against
   *any* network leakage) and `D-3` (no `INTERNET` permission) all stand. Backups arrive as files —
   via a watched drop folder or a browser upload — and Tryst never opens a socket.
   *Guard:* none possible in this repo; enforced by review. Any proposal that adds a network client
   to Tryst is a **new ADR in the Tryst repo**, not a task here.

2. **No plaintext of user data is ever written to the array.** appdata holds only (a) opaque
   `TRYSTBK1` blobs exactly as Tryst wrote them, and (b) a derived index encrypted under the runtime
   key. Decrypted `data.json` and media exist only in memory or tmpfs, for the life of a request.
   *Guard:* `scripts/guards.sh no-plaintext` — armed since M3: it runs a full ingest+index cycle against
   a temp dir and fails if any file in the vault is readable as ZIP/JSON or carries a sentinel string.

3. **The key is never at rest.** No passphrase, key, or derived key material in the image, in
   `docker-compose.yml`, in a `.env` on the array, or in appdata. The container starts **locked**;
   a human unlocks it after every start. Reboot re-locks.
   *Guard:* `scripts/guards.sh no-secrets` — fails if `.env` or any key-shaped file is tracked, or
   if a long literal is assigned to a password/passphrase/secret name in source. The **image** is
   covered separately by CI's trivy secret scan; the local guard reads the repo only.

4. **No secrets in version control, ever.** Includes real `.tryst` files — they are real intimacy
   data. `*.tryst`, `inbox/`, `vault/` and `testdata/real/` are gitignored. Test fixtures are
   **synthetically generated** at test time, never committed.
   *Guard:* trivy secret scan + the gitignore; `make guard-no-secrets`.

5. **Ingested blobs are immutable and tamper-evident.** A stored backup is never rewritten in place.
   Every blob gets a SHA-256 recorded at ingest and re-verified on read; `TRYSTBK1`'s AEAD
   authenticates the stream, so a modified byte fails to decrypt. Same idiom as the `immich-backup`
   script's manifest.
   *Guard:* round-trip + corruption tests in CI (flip a byte → verification must fail).

6. **Container is least-privilege.** Non-root, read-only rootfs, all capabilities dropped, no host
   network, only the one intended port published, base image pinned **by digest**, memory/CPU limits
   set, healthcheck present, SIGTERM handled.
   *Guard:* `scripts/guards.sh digest-pin` (stricter than a no-`:latest` check — it requires
   `@sha256:` on **every** `FROM`), plus `.github/workflows/ci.yml`: `docker inspect` non-root
   assertion, a compose exposure/limits check, and a trivy vuln+secret scan on the built image.
   SIGTERM handling cannot be verified on Windows; `scripts/smoke-live.sh` proves it with `docker stop` on a real Docker host (N11).

7. **LAN-only in v1.** No port forwarding, no public DNS, no reverse proxy to the internet. Remote
   access, if it ever happens, is Tailscale/WireGuard — never an exposed port.
   *Guard:* review + `RUNBOOK.md`; the compose file binds the published port explicitly.

---

## What it does (v1 scope)

- **Ingest** `TRYSTBK1` backups from a watched drop folder and from a browser upload.
- **Verify** each one: magic/header/version parse, SHA-256, and a real trial decrypt proving the
  stored password opens it — a backup that can't be opened is not a backup.
- **Retain**: versioned history per owner, configurable retention/prune, immutable blobs.
- **Alert** when the newest backup for an owner goes stale (Unraid notification, same posture as
  `immich-backup --remind`: monthly nudge, escalating).
- **Restore**: hand back an exact byte-identical `.tryst` file for any retained version.
- **Web UI**: responsive, light/dark/auto theme, built-in help, upload progress, optional password hints
  (D-22). Plain HTML and CSS plus one same-origin script; strict CSP.

**Out of scope for v1:** viewing/browsing encounter data; partner sharing or any merged view; any
change to the Tryst app; internet exposure; mobile push; multi-tenant beyond two owners; automated
ingestion *from* the phone (the transfer is Syncthing/SMB/SAF's job, not ours).

The data model is **multi-owner from day 1** even though v1 provisions one owner — retrofitting an
ownership column onto a shipped schema is exactly what principle 2 forbids.

See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

---

## Tech stack

- **Language / runtime:** Go (see [SETUP.md](SETUP.md) for the pin). Single service, single binary.
- **Crypto:** `tink-go` — official `AesGcmHkdfStreaming`, the same primitive Tryst encrypts with.
  PBKDF2-HMAC-SHA256 from `golang.org/x/crypto` for the TRYSTBK1 key + owner login (D-14).
  **Argon2id** (`golang.org/x/crypto/argon2`) for vault unlock — the memory-hard KDF wins
  against the offline attack model on the sealed index (D-16). AES-256-GCM (stdlib) for the
  seal itself. **Never hand-roll the streaming AEAD.**
- **Index:** SQLite via **`modernc.org/sqlite`** (pure Go — cgo-free). Lives on **tmpfs**
  while unlocked, sealed back to the array as an AES-256-GCM blob. Chosen over SQLCipher
  specifically to avoid cgo and keep the static binary (D-5).
- **HTTP:** stdlib `net/http`. No web framework.
- **Build:** `go build`; `make` for tasks; multi-stage `Dockerfile` → distroless, non-root.
- **Test:** `go test ./...`, fixtures generated synthetically at test time.
- **Deploy:** `docker compose` on Unraid.

## Architecture

One Go service. A watcher and an HTTP handler both feed a single **ingest pipeline** (verify → hash →
store blob immutably → index). The index and every stored blob are encrypted under a **runtime key**
that exists only in process memory, derived from a passphrase a human enters after each container
start; until then the service serves nothing but the unlock page and `/healthz`. Details in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Current state

v0.1.1 is released (GHCR image per tag, `:stable` follows the latest). Milestones M0 to M6 are done; see
[docs/ROADMAP.md](docs/ROADMAP.md) for releases and the backlog. Releases are cut with `scripts/release.sh`.

## Build & run

```
# one-command bootstrap (Windows dev box)
.\bootstrap.ps1

# common tasks
make build          # compile to ./bin/
make test           # go test ./...
make lint           # go vet + gofmt check
make guards         # the constraint guards from CLAUDE.md
make image          # build the container image
make check          # everything CI runs, locally
```

> Toolchain pins and environment gotchas live in [SETUP.md](SETUP.md) — read it before the first build.

## Key documents

- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/DATA_MODEL.md](docs/DATA_MODEL.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/DECISIONS.md](docs/DECISIONS.md) — ADR log
- [CHANGELOG.md](CHANGELOG.md)
- [RUNBOOK.md](RUNBOOK.md) — start/stop, unlock, backup/restore, rollback
- [CRITICAL_ASSETS.md](CRITICAL_ASSETS.md) — what git deliberately doesn't hold
