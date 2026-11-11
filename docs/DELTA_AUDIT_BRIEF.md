# Delta-audit brief (pre-v0.1.0)

> **Historical:** written 2026-11-10 for the v0.1.0 review. Line numbers and file references describe that
> range and are kept as a record; the current state is in [../CHANGELOG.md](../CHANGELOG.md).

Hand-off for a fresh-eyes auditor session. Lens: **delta-audit** (checklist 02, prompt P03).
Written 2026-11-10. Do not trust the author's claims below; they say where to look, not what to conclude.

## Range

The post-freeze range (everything after the commit that applied the
Phase 3 audit findings F01-F07 on 2026-08-23. The existing audit report is `docs/AUDIT.md`.

About 2,100 lines changed. Ignore the brand-mark header/footer comment blocks (14 lines at the
top and a trace line at the bottom of most source files); they are comments only.
Ignore `docs`, `*.md` and `*_test.go` to see the real surface.

## What changed, by risk area (read these first)

1. **New outbound network code** (Sanctum now makes its own HTTPS calls; before, it made none).
   - `internal/notify/url.go`: built-in notifier. `SANCTUM_NOTIFY_URL` accepts ntfy, Discord, Slack,
     generic webhook, up to 4 comma-separated. The URL is a credential. Check: is it ever logged or
     echoed (UI, errors, `-notify-test` output, Describe())? Redirect handling, TLS verification,
     timeouts, response-size bounds, header/body injection from event text, what an operator-supplied
     URL can reach (SSRF into the LAN is the operator's own choice, but is anything user/backup-controlled
     ever interpolated into the URL or headers?).
   - `internal/updatecheck/updatecheck.go`: opt-in (`SANCTUM_UPDATE_CHECK`), reads the GitHub releases
     API. Check: URL pinning, redirect refusal, response parsing/size limits, what it does with
     attacker-influenced release text (rendered in the UI banner: html/template escaping), and that it
     only reports and never downloads or executes anything.
2. **Upload handler** `internal/httpapi/server.go` `handleUpload` (the last commit before the audit). It replaced
   `ParseMultipartForm` with `MultipartReader` streaming into `ingest.IngestReader`, plus an early
   `Content-Length` rejection. Check the size cap holds for chunked and lying clients, partial-read
   cleanup of the tmpfs staging file on every error path, auth ordering, filename handling, and that
   the F02 guarantees in `docs/AUDIT.md` still hold.
3. **Setup/auth flow**: first-run "type it twice" for the vault passphrase (`handleUnlock`,
   `Vault.FirstRun()` = no sealed index) and owner provisioning (`handleProvision`). Check that
   `FirstRun` cannot be forced on an existing vault (a way to make an attacker's passphrase the vault's),
   and that error/timing behaviour did not regress (F04 sentinel path, rate limiting).
4. **Release pipeline** `.github/workflows/release.yml` (never run yet). Check: trigger scope, token
   permissions (least privilege), action pinning, anything an untrusted PR or tag could influence,
   Trivy gate actually blocks, provenance/SBOM/attestation wiring, `:stable` tag movement, no secrets
   in logs.
5. **Container and Unraid template**: `Dockerfile` (HEALTHCHECK, builder digest pin, Go 1.26.11),
   `deploy/unraid-template.xml` (ExtraParams hardening flags, masked fields, `<Icon>` URL),
   `docker-compose.yml` (image default now `ghcr.io/herbiewalker/sanctum:stable`, labels, 2G memory /
   1g tmpfs defaults). Does anything weaken constraint 6 (least privilege) or add exposure?
6. **Host scripts that run as root on Unraid**:
   - (`sanctum-update.sh` was removed after Pass 008; updates are manual, see D-19.)
   - `deploy/unraid-scripts/sanctum-notify-dispatch.sh`: parses JSON drop files with jq or sed and calls
     the Unraid `notify` tool. Check command/argument injection from event text into the shell.
   - `scripts/smoke-live.sh`: `rm -rf` guard on a directory name, docker run flags. Dev/ops tool only.
7. **Format change**: `internal/trystbk/header.go` and `format.go` now accept container v1 and v2 (v2 =
   same crypto, plus an optional `settings.json` in the ZIP that Sanctum stores unread). Check that
   nothing reads `settings.json`, that unknown versions still fail closed, and the new
   `errors.Is(err, ErrUnsupportedVer)` mapping in `humanizeIngestErr` (`%w: %w` wrapping in ingest).
8. **Config and misc**: `internal/config/config.go` (float env parsing for alert hours, new vars),
   `cmd/sanctum/main.go` (`-healthcheck`, `-notify-test`, version), `internal/vault/vault.go`.

## Not in scope / already verified (do not redo, but do challenge the evidence)

- Live smoke run on the real host passed 11/11 on 2026-11-09 (`scripts/smoke-live.sh`): no-tmpfs refusal,
  413 on a 600 MB upload, tampered manifest salt, KDF floor, restore, graceful shutdown.
- CI green on the pre-audit tip: vet, gofmt, tests, guards, govulncheck, Trivy image scan.
- A real 419 MB v2 backup was ingested, returned byte-identical, and restored into Tryst on an emulator.

## Known and accepted (flag only if you disagree with the reasoning)

- LAN-only HTTP, session cookie not `Secure` over plain HTTP (D-17).
- Go may keep copies of the runtime key in memory (existing accepted residual risk, `docs/AUDIT.md`).
- `deploy/` hardening flags are under owner review (may trim some in the template); not a finding by itself.
- Upload/download progress UI is backlog (`docs/ROADMAP.md`); the 419 MB upload looks frozen for minutes.

## Constraints to hold the code against

`CLAUDE.md` hard constraints 1-7 (no plaintext on the array, key never at rest, no secrets in git,
immutable blobs, least-privilege container, LAN-only). Pay special attention to 3 (a notification URL
or webhook token is a secret: is it in git, logs, the image, or UI?) and 6.

## Deliverable

Findings table (severity blocker / should-fix / nit, file:line, issue, concrete fix) as a new numbered
audit report section in `docs/AUDIT.md`, with a GO / NO-GO for v0.1.0. Verify claims by running things
(`go vet`, `go test ./...`, `scripts/guards.sh`, building the image) and show output. Do not apply fixes
in the audit session; report them, and the owner approves what gets changed. Zero findings is a valid
result. Off-lens notes go in one line at the end.
