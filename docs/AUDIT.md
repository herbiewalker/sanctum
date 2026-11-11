# AUDIT.md — Sanctum pre-release audit log

Log of Phase 3 (checklist 02) audit passes. One entry per pass. Each pass is one
lens, done in a fresh session where practical.

The verdict at the bottom of each pass is what the release gate reads. A pass
that ends NO-GO must be re-run after its blockers are fixed; the re-run is a
new entry, not an edit.

---

## Pass 001 — crypto + secrets-storage-logging (combined)

- **Date:** 2026-08-23
- **Lens:** crypto primitives, KDFs, key management, at-rest storage,
  secrets/logging flow
- **Auditor:** fresh session (no prior code-writing context on this repo)
- **Scope in:** `internal/vaultkey`, `internal/index/seal.go`,
  `internal/trystbk` (header, format, reader), `internal/vault` (vault +
  manifest), `internal/session`, `internal/httpapi/server.go` +
  `httpapi/rate.go`, `internal/ingest/ingest.go`, `internal/blobstore/store.go`
  (Put path only), log call sites across `internal/` and `cmd/`.
- **Scope out (off-lens):** dependency CVEs and licences, wider network surface
  beyond the auth endpoints' shape, container hardening, UI/accessibility.
  Anything noted incidentally is listed under "Off-lens observations".
- **Verification run:** `bash scripts/guards.sh` on the audit host — digest-pin
  and no-secrets passed; no-plaintext could not run here (Go toolchain absent
  on this host: `go: command not found`). Must be re-run on the dev/CI host.

### Findings

Severity legend: **blocker** = ships-block, **should-fix** = fix before release
unless explicitly accepted as residual risk, **nit** = quality only.

#### F01 — [blocker] TmpDir silently falls back to on-disk `/tmp`

- **Where:** `internal/vault/vault.go:91-93`, `internal/ingest/ingest.go:123-125`
- **Issue:** `Vault.New` and `ingest.New` both fall back to `os.TempDir()` when
  `Paths.TmpDir` / `Options.TmpDir` is unset. CLAUDE.md hard constraint 2
  requires TmpDir to be a **tmpfs** mount in production — the decrypted `data.json`
  and the live SQLite index materialise there. A compose file that forgets the
  `tmpfs:` stanza runs plaintext through the on-disk `/tmp` on the array with
  no failure signal. The `no-plaintext` guard catches this in CI but nothing
  catches it at runtime.
- **Failure scenario:** Operator deploys a compose file missing
  `tmpfs: /tmpfs`. Sanctum starts, ingests a real backup, writes
  `ingest-*.tmp` (decrypted staging) and `index.*.tmp.sqlite` (during
  `Serialize`) to the array-backed `/tmp` inside the container. Depending on
  Docker's storage driver, those bytes hit the array and survive the container
  lifetime as reclaimed-but-recoverable inode data.
- **Fix (proposed):**
  1. Remove the `os.TempDir()` fallback in `Vault.New` — return an error if
     `Paths.TmpDir` is empty.
  2. Add an explicit `Paths.AllowNonTmpfsTmpDir bool` opt-in for tests and
     local dev; production wiring in `cmd/sanctum/main.go` leaves it false.
  3. On startup, `statfs` `TmpDir` and refuse to start unless
     `f_type == TMPFS_MAGIC` (0x01021994) OR `AllowNonTmpfsTmpDir` is true.
     Linux-only check; on Windows dev the opt-in is required.
  4. Do the same for `ingest.New` — but since `Service` is only constructed
     by `Vault.Unlock`, enforcing at the Vault layer is sufficient. Drop the
     ingest fallback and require the field.
- **Verify:** unit test (Vault.New with empty TmpDir → error), an integration
  test that spins up in a tmpdir with the opt-in and one that fails without it.

#### F02 — [blocker] Multipart parser can buffer 1 GiB in RAM

- **Where:** `internal/httpapi/server.go:401`
- **Issue:** `r.ParseMultipartForm(1 << 30)` sets the in-memory threshold for
  the multipart parser to 1 GiB — twice the container's default 512M memory
  limit and 2× `trystbk.MaxBackupBytes` (512 MiB). A hostile authenticated
  client (or a mis-sent legitimate upload) can OOM-kill the container before
  the ingest-side `LimitReader` fires.
- **Failure scenario:** Authenticated caller POSTs `/upload` with a
  1 GiB multipart body. Go's `net/http` calls `ParseMultipartForm(1<<30)`,
  which materialises the whole part in `bytes.Buffer` because 1 GiB fits in
  the "in memory" branch. Container hits its 512M cgroup limit, OOM killer
  kills PID 1, service dies mid-request; every open session ends.
- **Fix (proposed):**
  1. Lower `maxMemory` to something small (e.g. 16 MiB) — the rest spills to
     `TmpDir` (which #F01 will now correctly force to tmpfs).
  2. Wrap `r.Body` in `http.MaxBytesReader(w, r.Body, MaxBackupBytes+8<<10)`
     before `ParseMultipartForm` so oversized bodies get a clean 413 instead
     of a partial parse.
  3. Add a test that a 600 MiB upload is rejected fast, not buffered to RAM.
- **Verify:** metrics or a manual `curl` with a 600 MiB body should return
  413 in single-digit ms, and RSS should not spike.

#### F03 — [should-fix] `IsInsecureForTest` is documented as a production guard but never invoked on the production path

- **Where:** `internal/vaultkey/vaultkey.go:103-108` (definition, with a
  docstring promising production callers assert against it) and
  `internal/vault/vault.go:181` + `internal/vault/manifest.go:39-79`
  (the two places that would need to call it and don't).
- **Issue:** Grep confirms the only callers are tests. If `manifest.json` is
  hand-edited to lower KDF cost, or a code bug causes `TestParams` to be
  minted at first-run instead of `DefaultParams`, `Vault.Unlock` silently
  derives under microsecond-cost params and the operator has no signal. The
  guard's floor is also very loose: it trips only at `Time≤1 && Mem≤64 KiB
  && Par≤1`, so a manifest with e.g. `t=2, m=1024, p=1` slips past despite
  being trivially crackable.
- **Failure scenario:** A future maintainer copy-pastes a test scaffold that
  writes a manifest with `TestParams` values into a real vault. Unlock
  succeeds with a millisecond-fast KDF; the sealed index's effective offline
  cost drops from ~2^40 guess-seconds to seconds. No log, no error.
- **Fix (proposed):**
  1. Introduce `vaultkey.ProductionFloor` (constants: `MinTime=3`,
     `MinMemoryKiB=64*1024`, `MinParallel=1`) and a `ValidateProduction(p
     Params) error` function.
  2. Call `ValidateProduction` from `LoadOrCreateManifest` after reading
     the manifest, and again from `Vault.Unlock` before `Derive`. Return
     a distinct error (`ErrKDFBelowProductionFloor`) so operators see the
     reason.
  3. Keep `IsInsecureForTest` for what its name says (test detection);
     don't overload it with the production floor.
  4. Update the docstring on `IsInsecureForTest` to stop claiming a
     production role.
- **Verify:** unit test — write a manifest with `TestParams` at production
  path, expect `ErrKDFBelowProductionFloor` on Unlock.

#### F04 — [should-fix] Login timing side-channel is only partially defended

- **Where:** `internal/httpapi/server.go:344-357`
- **Issue:** The "unknown user" branch runs a dummy PBKDF2 and returns,
  skipping the DB round-trip AND the `subtle.ConstantTimeCompare` that the
  success branch runs. Wall-time between the two branches differs by at
  least one DB read plus one 32-byte compare — measurable over enough
  samples on a LAN. The dummy also hardcodes `iters=600_000`; if a future
  owner is provisioned with different iterations, the dummy diverges from
  reality on that axis too. And the dummy salt is 19 bytes despite being
  labelled "16bytes" (see F06).
- **Failure scenario:** LAN attacker (T2) enumerates usernames by
  measuring login latency across the two branches. Discovering valid
  usernames is not by itself a compromise — but it narrows the
  brute-force target set, especially in a two-owner deployment where
  discovering "there are exactly N owners with these labels" is
  meaningful.
- **Fix (proposed):** the code already tries to defend; make the defence
  structural rather than approximate:
  1. Always fetch (or run a same-shape sentinel query for the miss case).
  2. Always run PBKDF2 with the row's iterations if present, else with a
     fixed `defaultLoginIters` constant that matches `deriveOwnerLogin`.
  3. Always run `subtle.ConstantTimeCompare` on both branches — for the
     miss case, compare `pbkdf2.Key(pw, sentinelSalt, defaultLoginIters,
     32, sha256.New)` against a 32-byte zero slice; the result is
     discarded, only the time matters.
  4. Alternative: accept the leak explicitly (LAN-only, D-12) and drop the
     dummy so the code doesn't misrepresent its own defence. Prefer this
     if enumeration is genuinely acceptable — document in `THREAT_MODEL`.
- **Verify:** micro-benchmark the two branches and assert they're within
  ~5% of each other under load.

#### F05 — [should-fix] `manifest.json` is not authenticated

- **Where:** `internal/vault/manifest.go:39-79`,
  `internal/index/seal.go:54-82`
- **Issue:** The manifest is cleartext JSON carrying the KDF stanza (salt,
  cost, algorithm). An attacker with write access to `VaultDir` (T3
  host-filesystem write) can rewrite any field. In practice the seal was
  produced under the *old* Params so unlock fails GCM auth and the vault
  refuses to open — a denial-of-service, not key recovery. But the operator
  sees `ErrBadPassphrase` and has no way to distinguish "I typed it wrong"
  from "someone tampered with my vault".
- **Failure scenario:** Attacker with a foothold on the host swaps the
  manifest salt. Operator sees repeated "wrong passphrase" and eventually
  triggers a manual re-derive from a backup manifest they may not have kept
  (nothing in the setup docs asks them to). Vault effectively bricked.
- **Fix (proposed):**
  1. In `SealBytes`, extend the associated-data to include the manifest's
     KDF bytes (a canonical JSON of the `KDF` field). Bind manifest and
     seal cryptographically: a manifest that has changed since the seal
     was written fails to open with a distinct error surface even before
     GCM completes.
  2. Return a distinct error class (`ErrManifestOutOfBand`) from
     `UnsealFile` when the associated-data mismatch is detected, so the
     operator sees "your `manifest.json` no longer matches the seal it
     produced" instead of "wrong passphrase".
  3. Add a migration path: existing seals were written without the extra
     AD; either bump `sealVersion` to 2 and keep v1 read-compat, or
     re-seal on first successful unlock under the new version.
- **Verify:** test that flipping any byte of `manifest.json` (other than
  cosmetic whitespace outside the KDF stanza) surfaces the new error.

#### F06 — [nit] Dummy salt label is wrong

- **Where:** `internal/httpapi/server.go:348`
- **Issue:** Literal is `"dummy-salt-16bytes!"` which is 19 bytes, not 16.
  Cosmetic only — the salt used for a dummy PBKDF2 doesn't need any
  particular length — but the label lies about it.
- **Fix (proposed):** Drop the label entirely if F04 restructures this
  branch; otherwise use a plain 16-byte constant literal.
- **Status:** resolved as a side-effect of F04 — the whole dummy branch
  was replaced by `sentinelOwnerAuth()`.

#### F07 — [nit] `Key.Bytes()` returns an aliasing slice

- **Where:** `internal/vaultkey/vaultkey.go:126-137`
- **Issue:** `Bytes()` returns `k.bytes[:]`. `Zero()` wipes the backing
  array. Any caller that stashes the slice past a `Zero()` sees zeros
  silently. All current callers use it synchronously (verified by reading
  the vault, index seal, and blobstore paths), so this is a footgun for
  future code, not a live bug.
- **Fix (proposed):** rename current method to `BytesUnsafe()` for the
  hot path (aliasing, documented) and add `Bytes() []byte` that returns
  a fresh copy. Update the two seal call sites; the extra 32-byte copy is
  irrelevant against Argon2id's cost.

### Off-lens observations (not chased)

- **Network-surface:** rate limiter is per-IP with an "arbitrary bucket
  eviction" policy at the 4096-key cap; on a LAN this is fine, but a
  future public-exposure story would want LRU. `X-Forwarded-For` is
  trusted unconditionally in `clientIP()`; noted in the code, correct
  for D-12 posture.
- **Threat-model documentation:** backup passwords live in the sealed
  SQLite index cleartext while unlocked (D-13/F18 requires it). This is
  by design, but `THREAT_MODEL.md` should restate it explicitly so a
  reader doesn't have to reconstruct it from code.

### What this pass covered

- KDF algorithm and parameter choice (Argon2id vault; PBKDF2-HMAC-SHA256
  for TRYSTBK1 and owner login) — sound, at OWASP-2023 defaults.
- AEAD selection: AES-256-GCM (stdlib) for the seal, AES-256-GCM-HKDF
  streaming via tink-go for TRYSTBK1. No hand-rolled modes.
- Nonce handling: fresh 12-byte GCM nonce per seal, no reuse pattern;
  associated-data binds the seal header.
- Random generation: all `crypto/rand` — no `math/rand` reachable in
  crypto paths.
- Key lifecycle: derived on Unlock, held in a `[32]byte` field, zeroed on
  Lock and on Unlock's failure paths; every current `Bytes()` caller
  consumes synchronously.
- Session cookie handling: 32 random bytes, base64url, cleared on Lock via
  `Manager.Clear()`, `HttpOnly` + `SameSite=Strict` + `Secure` when TLS.
- Logging: grepped every `logger.` / `slog.` call site — no passwords, no
  filenames beyond the ingest source label, no encounter content; SHAs
  truncated to 16 hex chars; ingest event details neutral (`sha=… reason=…`).
- Constraint guards: `digest-pin` OK, `no-secrets` OK.

### What this pass cannot cover (human-only)

- `guards.sh no-plaintext` needs a real Go toolchain (this host has none)
  — re-run on the dev/CI host and confirm PASS on the release build.
- Runtime memory hygiene against a hot attacker with process-memory access
  (compiler register/stack copies of the key that `Zero()` cannot reach) —
  Go gives no guarantee here; dynamic analysis territory.
- The image-level trivy secret scan runs in CI, not against the repo.
- Real-device end-to-end (unlock → drop-folder ingest → restore) with
  observed wire traffic.

### Verdict for the go/no-go

**NO-GO** for release until F01 and F02 are fixed. Both can turn a
configuration oversight into a hard constraint violation (F01: plaintext
on the array; F02: OOM-kill from a hostile upload). F03 and F04 are strong
should-fixes — F03 restores a guarantee the docstring already claims, F04
fixes a defence that is currently only partial. F05–F07 are quality
improvements.

**Residual risks accepted (proposed):** compiler-retained key material in
Go (mitigation is best-effort by design); rate-limiter eviction under IP
scan (LAN-only posture makes this acceptable); backup passwords cleartext
in the sealed index (required by D-13, restate in THREAT_MODEL).

**Human-only checks outstanding:** re-run `no-plaintext` guard on a Go
host; run image-level trivy scan; real-device end-to-end.

### Fix plan → next steps

Fixes will land as separate commits, each with the F-id in the message.
After F01–F04 are in, this pass re-runs (Pass 002) against those files
plus a re-grep of log sites — a delta-audit, not a full crypto pass.

---

## Pass 002 — crypto delta-audit + verification

- **Date:** 2026-08-23 (same day, same session — the fresh-eyes rule matters
  most for the initial pass; a delta-audit is by definition a re-read of
  work the auditor just did.)
- **Lens:** delta-audit of the files touched by F01–F07.
- **Scope in:** `internal/vaultkey/{vaultkey.go,vaultkey_test.go}`,
  `internal/index/{seal.go,index_test.go}`,
  `internal/vault/{vault.go,vault_test.go,binding.go,tmpfs_linux.go,tmpfs_other.go}`,
  `internal/ingest/ingest.go`, `internal/httpapi/{server.go,server_test.go}`,
  `internal/config/config.go`, `cmd/sanctum/main.go`, `docs/AUDIT.md`.
- **Scope out:** anything not touched by F01–F07.

### Verification runs

All executed on this host with `go1.26.7 windows/amd64` (Go bin was at
`C:\Program Files\Go\bin\` — added to PATH for the run).

- `go build ./...` → clean (one iteration: initial build reported
  `undefined: http.ErrRequestBodyTooLarge`, since that sentinel does not
  exist in stdlib; `isBodyTooLarge` was rewritten to rely on
  `*http.MaxBytesError` via `errors.As` plus a string-match fallback for
  the wrapped case `ParseMultipartForm` produces).
- `go vet ./...` → clean.
- `go test ./...` →
  ```
  ok  internal/blobstore   ok  internal/config      ok  internal/httpapi
  ok  internal/index       ok  internal/ingest      ok  internal/notify
  ok  internal/retention   ok  internal/scheduler   ok  internal/session
  ok  internal/trystbk     ok  internal/vault       ok  internal/vaultkey
  ok  internal/verify      ok  internal/watcher
  ```
- `bash scripts/guards.sh` (Docker digest-pin, no-secrets, and — for the
  first time on this host — the previously-blocked no-plaintext guard) →
  ```
  OK  digest-pin: every FROM pinned by @sha256:
  OK  no-secrets: no tracked secrets, no hardcoded credentials
  OK  no-plaintext: full ingest cycle wrote no plaintext to vault dir
  guards passed
  ```
- Every new F-tagged test executed and passed:
  - F01 — `TestNew_RejectsEmptyTmpDir`,
    `TestNew_RejectsTmpDirEqualToVaultDir`
  - F02 — `TestUpload_OversizeBodyRejectedWith413_F02`
  - F03 — `TestDefaultParams_MeetsProductionFloor`,
    `TestValidateProduction_RejectsTestParams`,
    `TestValidateProduction_BoundaryPerAxis`,
    `TestUnlock_RejectsBelowProductionFloor_F03`
  - F05 — `TestSealBytes_ManifestBindingF05`,
    `TestUnlock_TamperedManifestSurfacesOutOfBand_F05`
  - F07 — `TestKey_Bytes_ReturnsCopy_F07`,
    `TestKey_BytesUnsafe_Aliases_F07`

### Findings

None. Delta re-read found no regressions and no new issues in the touched
files.

Two small properties worth calling out from the re-read:

- **F05 wire-format change is genuinely load-bearing.** Every path that
  ever writes a seal now uses the v2 header (52 bytes) and threads a
  binding through; every path that reads one requires the current
  manifest binding to match. `.prev` fallback correctly short-circuits
  on `ErrSealManifestOutOfBand` — retrying the previous generation
  under a changed manifest is guaranteed to fail identically, and the
  operator gets one clean error instead of two.
- **F07 has no leftover aliasing.** The two production `Bytes()` callers
  (`vault.Lock` → `sealAndClose`, `unsealOrOpen` → `index.UnsealFile`)
  both use the value synchronously; nothing stashes the returned slice.
  The `BytesUnsafe` escape hatch has zero call sites outside its test.

### What this pass cannot cover (still human-only)

- Compose-without-tmpfs smoke on real Unraid (F01's runtime backstop).
  The unit tests cover the empty/mismatched-path guards; the Linux
  `statfs` branch is exercised only when someone actually runs the
  container on Linux without the tmpfs mount. Deferred to M6
  deploy-to-Unraid.
- 512 MiB `curl` smoke against a running server (F02) — the unit test
  runs with shrunk limits to keep the assertion cheap; the real cap is
  512 MiB.
- Image-level trivy secret scan (CI, not this host).
- Real-device end-to-end (unlock → drop-folder ingest → restore).

### Verdict for the go/no-go

**GO**, conditional on the three human-only smokes above being run
during M6 deploy-to-Unraid.

Residual risks accepted:

- Go compiler may retain register/stack copies of the runtime key that
  `Key.Zero()` cannot reach — best-effort against a crash-dump attacker,
  no defence against a live process-memory attacker.
- Rate limiter is per-IP with a "delete an arbitrary bucket at 4096"
  eviction — LAN-only posture makes this acceptable.
- Backup passwords sit cleartext in the sealed SQLite index while
  unlocked, on the F01-guarded tmpfs mount — required by D-13/F18 so
  ingest can open new backups without operator input. Restate in
  `THREAT_MODEL.md` next time it is touched.

---

## Pass 003 — dependencies & licenses

- **Date:** 2026-08-23
- **Lens:** transitive dependency CVEs + license compatibility + supply-chain
  hygiene (checksums, verifiable pins).
- **Verification runs:**
  - `go mod verify` → `all modules verified`.
  - `govulncheck ./...` (`golang.org/x/vuln v1.7.0`): **0 reachable
    vulnerabilities**, 1 unreachable advisory:
    - GO-2026-5932 — `golang.org/x/crypto/openpgp` unmaintained. Sanctum
      does not import it (`govulncheck` confirms "your code doesn't appear
      to call these vulnerabilities").
- **License survey** (all direct + transitive):
  - Apache-2.0 — `tink-crypto/tink-go`, `google/uuid`.
  - BSD-3-Clause — `golang.org/x/*`, `modernc.org/*` chain, `mattn/go-isatty`,
    `ncruces/go-strftime`.
  - MIT — `dustin/go-humanize`, `remyoudompheng/bigfft`.
  - No GPL/AGPL/copyleft in the graph. Everything compatible with a
    permissive homelab redistribution stance if Sanctum ever goes public.
- **Findings:** none.
- **Verdict:** GO. Residual: govulncheck is an on-demand scan and should
  be added to CI (deferred to M6 CI-refresh).

---

## Pass 004 — network & exposed surface

- **Date:** 2026-08-23
- **Lens:** what listens, what talks out, how requests are authenticated
  and gated, response headers, TLS posture.
- **Verified:**
  - **Bind:** compose publishes `${SANCTUM_BIND_IP:-127.0.0.1}:${PORT}:8080`.
    Default is loopback-only; operator explicitly opts into LAN by
    changing `SANCTUM_BIND_IP`. No `0.0.0.0` in the code path.
  - **Least-privilege container:** `user: 65532:65532`, `read_only: true`,
    `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`,
    `deploy.resources.limits { memory, cpus }` present. `tmpfs` mounted
    `noexec,nosuid,nodev`.
  - **Route inventory** (grepped from `Routes()` and each handler's gate):
    - Always: `GET /healthz`, `GET /`.
    - Vault-state gated (`IsUnlocked` check in every handler beyond root):
      `POST /unlock`, `POST /lock`, `POST /login`, `POST /logout`,
      `POST /provision`, `GET /status`, `POST /upload`, `GET /restore/{id}`,
      `GET /passwords`, `POST /passwords`, `POST /passwords/{id}/delete`.
    - Method-strictness enforced by Go 1.22+ ServeMux — other methods
      return 405.
    - `POST /unlock` and `POST /login` gated by the F04-updated login
      handler and per-IP rate limiter (5/60s and 10/20s).
    - `POST /provision` refuses after any owner exists (first-run only).
  - **Response headers:** every render sets `Content-Type`,
    `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
    `Referrer-Policy: no-referrer`.
  - **Cookies:** `HttpOnly`, `SameSite=Strict`, `Secure` when
    `r.TLS != nil`.
  - **Templates:** every expression is `{{.Field}}` (auto-escaped by
    `html/template`); no `template.HTML` / `safeHTML` bypass anywhere.
  - **Outbound:** no HTTP client, no DNS resolver call, no socket.Dial
    in production code (only `runHealthcheck` which hits loopback).
- **Findings:**
  - **N01 [nit]** No `Content-Security-Policy` header. Templates are
    static and cannot embed user HTML today; CSP would be defence-in-depth
    against a future template regression. Low impact, LAN-only.
  - **N02 [nit]** No `X-Frame-Options: DENY` / `frame-ancestors 'none'`
    header. Clickjacking of the unlock form is technically possible from
    a foreign origin, but SameSite=Strict makes the resulting submission
    inert. Low impact.
- **Off-lens:** rate-limiter's arbitrary-eviction policy at 4096-key cap
  was noted in Pass 001; still fine on LAN.
- **Verdict:** GO. Recommend adding CSP + X-Frame-Options in a future
  minor tick when the templates are next touched.

---

## Pass 005 — input & injection

- **Date:** 2026-08-23
- **Lens:** every untrusted-input boundary (HTTP form fields, uploaded
  files, inbox files, path parameters, query strings). SQL injection,
  command injection, path traversal, deserialization, XSS, DoS via
  crafted sizes/counts.
- **Verified:**
  - **SQL:** grepped every `db.Exec`/`db.Query`/`tx.Exec`/`QueryRow`/
    `Prepare` site — all parameterized (`?` placeholders). One
    `fmt.Sprintf("VACUUM INTO %s", quoteSQLLiteral(tmpPath))` — path is
    server-generated via `os.CreateTemp`, and `quoteSQLLiteral` doubles
    embedded single quotes anyway.
  - **Path traversal:** blobstore `validateID` allows only
    `[A-Za-z0-9_-]`, max 128 chars — blocks `.`, `/`, `\`, null. Both
    `Put` and `Get`/`Open` validate before joining. `/restore/{id}` also
    goes through a DB lookup first, so an attacker id can't touch the FS
    unless it matches a real backup row.
  - **Command execution:** no `exec.Command` or `os/exec` anywhere in
    production code.
  - **Deserialization:** JSON decode only for `manifest.json` and
    `state.json` (both server-authored); no `encoding/gob`; no
    reflection-driven decode of user data.
  - **File upload:** F02 bounds the request body via `http.MaxBytesReader`
    and the multipart parser at 16 MiB in-memory before spilling to
    tmpfs. Ingest's `LimitReader(MaxBackupBytes)` is the second gate on
    the decrypted body, with a one-byte overflow probe.
  - **TRYSTBK1 parser (attacker-supplied bytes):** magic checked before
    any KDF work; iteration count bounded to
    `[MinIterations, MaxIterations]`; header length validated; wrong
    password fails cleanly via AEAD.
  - **Upload filename:** stored parameterized in `backup.original_filename`;
    NEVER rendered in a template today, so XSS via a crafted filename is
    prevented at the render layer as well as the storage layer.
  - **Content-Disposition:** uses server-generated `shortHash(SHA)`, not
    the user filename — no HTTP response splitting surface.
- **Findings:**
  - **I01 [nit]** Watcher does not check whether inbox entries are
    regular files vs symlinks. Inbox is compose-mounted `:ro` so an
    attacker on the SMB/Syncthing share could inject a symlink. Any
    followed link either fails TRYSTBK1 parse (rejected, event-logged)
    or reads a bounded number of bytes from a container-visible path —
    no privilege gain, no plaintext leak. Note only.
- **Verdict:** GO.

---

## Pass 006 — build hardening

- **Date:** 2026-08-23
- **Lens:** release build reproducibility, debug/symbol stripping, static
  linking, absence of local paths / credential-shaped strings in the
  artifact, base image pins.
- **Verified:**
  - Reproduced the release build outside the container:
    `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" ./cmd/sanctum`
    → 15,372,450-byte static ELF.
  - `file` reports `ELF 64-bit LSB executable, x86-64, statically linked,
    Go BuildID=..., stripped`.
  - `readelf -l` — no `PT_INTERP` segment → no dynamic linker
    dependency.
  - `strings | grep -E '<username>|C:\\|/home/|/Users/|GOPATH'` → empty.
    `-trimpath` verified.
  - `strings | grep -iE '(password|secret|token|apikey)='` → empty.
  - Dockerfile: both `FROM` lines pinned by `@sha256:...` digest, guarded
    by `scripts/guards.sh digest-pin` (green).
  - Runtime stage: `distroless/static-debian12:nonroot`, `USER 65532:65532`
    stated explicitly for a CI `docker inspect` assertion.
- **Findings:** none.
- **Verdict:** GO.

---

## Pass 007 — UI / accessibility

- **Date:** 2026-08-23
- **Lens:** the four HTML pages (unlock, login, status, passwords) plus
  the shared layout. Semantic HTML, focus order, labelling, contrast,
  keyboard operability.
- **Verified:**
  - `<html lang="en">`, `<meta name="viewport">`, `color-scheme: light dark`.
  - Semantic landmarks: `<header>`, `<nav>`, `<main>`, `<footer>`.
  - Heading hierarchy: single `<h1>` per page, `<h2>` for sections.
  - Every `<input>` has a matching `<label for="id">` with the correct
    `id`. `autocomplete` hints (`current-password`, `new-password`,
    `username`) present so password managers behave.
  - `type="password"` on passphrase fields — never rendered visibly.
  - Buttons are real `<button type="submit">`, not `<div onclick>`.
- **Findings:**
  - **U01 [nit]** `.muted { color: #8888 }` (~53% alpha over the page
    background) reads roughly `#B5B5B5` on white — approx 2.3:1 contrast,
    below WCAG AA (4.5:1) for body text. Used only for hint text, but
    should be darkened.
  - **U02 [nit]** Custom `border` on `input`/`button` without a matching
    `:focus-visible` outline weakens the browser's default keyboard-focus
    indicator.
  - **U03 [nit]** Error boxes convey severity by red border/text only.
    Adding a text prefix ("Error:") or an `aria-live="assertive"` region
    would make screen readers announce it.
- **Verdict:** GO for a two-person household service. All three nits
  are cheap to fix and worth doing on the next template touch.

---

## Pass 008 — delta-audit, post-freeze changes up to the pre-v0.1.0 tip

- **Date:** 2026-11-10
- **Lens:** delta-audit of everything that landed after the F01–F07 freeze (about 2,100 changed
  lines excluding brand comments): built-in notifier, update check, streaming upload, first-run
  setup, release pipeline, Unraid template/compose/Dockerfile, host scripts, container v2.
- **Auditor:** fresh session, read-only. No fixes applied; nothing committed or pushed.
  Brief: `docs/DELTA_AUDIT_BRIEF.md`.

### What was run

| Check | Result |
|---|---|
| `go vet ./...` | clean |
| `gofmt -l .` | clean |
| `go test ./...` | all 15 packages `ok` |
| `bash scripts/guards.sh all` | digest-pin OK, no-secrets OK, no-plaintext OK |
| `CGO_ENABLED=0 GOOS=linux go build -trimpath` | OK |
| `govulncheck ./...` (latest) | 0 affecting vulnerabilities (3 in required modules, not called) |
| CI on the pre-release tip (`gh run list`) | success |
| Throwaway PoC tests (written, run, deleted; tree clean) | confirmed D01, D02, D03 below |

### Findings

| ID | Severity | File:line | Issue → fix |
|---|---|---|---|
| D01 | **blocker** | `internal/vault/vault.go` Unlock/Lock (seal only in `sealAndClose`, ~L347); `internal/index/seal.go:181` | **The index is sealed to disk only on `Lock()`/`Close()`.** Any unclean stop (power loss, OOM kill, `docker kill`, a stop that outlives the grace period, Unraid array stop) loses every index change since the last unlock: owners, backup passwords and the rows for every backup ingested in that session. The blobs stay on disk as unreferenced orphans that retention never prunes. On the first session there is no seal at all, so the vault silently reverts to "first run" (PoC: while unlocked, `index.sealed` absent, `FirstRun()==true`). Confirmed by `TestAuditNoSealUntilLock`. → Checkpoint-seal while unlocked: after each committed mutation (ingest success, provision, password add/delete, retention prune) or on a short timer when dirty, using the key already in memory. Add a test that kills the vault without `Lock()` and re-unlocks. Until then, state this limit in RUNBOOK. |
| D02 | **blocker** | `internal/vault/vault.go` `unsealOrOpen` (~L395); `internal/index/seal.go:176-200` | **Unlock fails open when `index.sealed` is missing but `index.sealed.prev` exists.** `unsealOrOpen` stats only `index.sealed`; on `ErrNotExist` it returns a fresh in-memory index without trying `.prev` (or `.tmp`) and without checking any passphrase. `SealFile` creates exactly that state between `Rename(seal→prev)` and `Rename(tmp→seal)` (a crash there, or a failure of the second rename), and the comment above it promises a "next-run recovery" that does not exist. `FirstRun()` uses `SealExists` (checks `.prev`) so it reports false, and the unlock page skips the type-twice box. PoC: `Unlock("WRONG-attacker-pass")` → `err=nil unlocked=true`. The next `Lock` then rotates the empty index over `.prev`, destroying the last good index. Confidentiality of blobs is not affected (they are Tryst-encrypted and the index key is not derivable), but this is an authentication bypass onto an empty vault plus permanent index loss. → Make "fresh index" require that none of `index.sealed`, `.prev`, `.tmp` exist; otherwise go through `UnsealFile` (which already falls back to `.prev`) and, if only a valid `.tmp` exists, authenticate and promote it. Add a test for the crash window. |
| D03 | should-fix | `internal/httpapi/server.go:747-758` (pre-existing, M4; not listed in the accepted risks) | **`clientIP` trusts `X-Forwarded-For` from anyone.** The comment says "only when the connection came from a private range"; the code has no such check. A LAN client rotating the header defeats both rate limiters: PoC 200 requests from one socket → 200 allowed (cap is 5/min); without the header → 5. Argon2id cost still slows an offline-style guess to a few per second, but the limiter is the documented control (N16) for brute-forcing the vault and owner passphrases, and the log `ip` field becomes spoofable. → Key on the host part of `r.RemoteAddr` via `net.SplitHostPort`. Honour XFF only for an explicitly configured trusted-proxy list (none exists today, so simply drop it). Note: behind Docker's userland proxy every client may share one source IP, which makes the bucket global; acceptable and stricter. |
| D04 | should-fix | `.github/workflows/release.yml:14-16, 103-109` | **Release trigger does not check what the tag points at.** Any `vX.Y.Z` tag pushed by anyone with write access publishes an image and moves `:stable`, including from an unreviewed branch commit or a lower version than the current release (silent downgrade for everyone on `:stable`). → In `publish`, `fetch-depth: 0` and require `git merge-base --is-ancestor "$GITHUB_SHA" origin/main`; only add the `:stable` tag when this tag is the highest `v*` tag; add a repository ruleset restricting creation of `v*` tags. |
| D05 | should-fix | `.github/workflows/release.yml:77`; `.github/workflows/ci.yml:116` | **`aquasecurity/trivy-action@master` is a moving ref** inside the job that holds `packages: write`, `contents: write`, `id-token: write`. A compromised action could push or attest anything. → Pin to a commit SHA (and ideally pin the other third-party actions the same way; the `@vN` tags on checkout/setup-go/docker/* are a nit). |
| D06 | should-fix | `.github/workflows/release.yml:59-96` | **The image that is scanned is not the image that is pushed.** "Build (local)" is scanned, then "Push" rebuilds from scratch. Inputs are pinned so they should match, but nothing proves it, and the gate then covers a different artifact than the one users pull. → Build once and push by digest to an untagged ref, scan that digest, and only then add `:<version>`/`:stable` (or `docker push` the already scanned local image). |
| D07 | should-fix | repo root (no `.dockerignore`; `Dockerfile:22 COPY . .`) | **No `.dockerignore`.** The whole checkout, including `.git`, any local `.env`, `inbox/`, `vault/`, `testdata/real/` and real `*.tryst` files, is sent to the Docker daemon and baked into the build-stage layers and the host's builder cache. The shipped image is clean (multi-stage, only the binary is copied), but `docker compose up --build` and `sanctum-update.sh` build from a live checkout on the Unraid host, and constraint 4's "real .tryst are gitignored" does not cover the Docker context. → Add `.dockerignore`: `.git`, `.env*`, `inbox/`, `vault/`, `testdata/real/`, `*.tryst`, `bin/`, `docs/`. |
| D08 | should-fix | `deploy/unraid-scripts/sanctum-update.sh:41, 134-139, 166-171` | **Root host script builds and runs whatever the fetched tag contains.** `--apply` runs `docker compose build` from the checked-out tag, i.e. the remote's Dockerfile executes as root-controlled Docker on the host. `REQUIRE_SIGNED` defaults to 0 and `git verify-tag` needs a keyring nothing sets up. The fast-forward check stops downgrades, not a malicious commit on top. The tag name is also used unvalidated in `git checkout` and printed raw into the JSON drop file in `emit` (a tag containing `"` breaks or injects into the intent; the dispatcher then passes it safely as an argument, so impact is notification text only). Mitigations that already hold: default mode is `--check`, `AUTO_APPLY` is opt-in, flock, rollback, clean-tree check. → Validate the tag against `^v[0-9]+\.[0-9]+\.[0-9]+$` before any use; default `REQUIRE_SIGNED=1` or, better, apply by pulling `ghcr.io/…@sha256:` and verifying the release attestation instead of building from source; document that `AUTO_APPLY=1` hands root-adjacent execution to the GitHub account. |
| D09 | should-fix (low) | `internal/httpapi/server.go` `handleUpload`; `internal/ingest/ingest.go:306` `stageInput`; `docker-compose.yml` tmpfs 1g | **Nothing bounds concurrent staging.** Each upload stages up to `MaxBackupBytes` (512 MiB) on the same 1 GiB tmpfs that holds the live SQLite index and the transient copy `Serialize` writes at `Lock`. Two simultaneous uploads (two owners, or an upload plus the watcher) can fill it: ingests fail with ENOSPC, and if the tmpfs is full when `Lock`/SIGTERM serialises the index, the seal fails and the key is zeroed anyway (`vault.go` Lock docstring), losing the session's index changes (compounds D01). → One global staging semaphore (return 503 "busy"); optionally reserve index headroom. |
| D10 | nit | `internal/notify/url.go:128-131` | Discord payload has no `allowed_mentions: {"parse": []}`; the stale-backup body interpolates the owner label, so a label of `@everyone` pings the channel. `truncate` cuts on bytes and can split a UTF-8 rune (JSON encoding substitutes U+FFFD, harmless). → Add `allowed_mentions`; truncate on rune boundary. |
| D11 | nit | `internal/updatecheck/updatecheck.go:236-243` | `parseSemver` uses `strconv.Atoi`, which accepts `+5`, so a tag like `v+1.+2.+3` passes and is stored as `Latest`. Rendered through `html/template` (escaped) and the link is restricted to `https://github.com/`, so no exploit. → Require digits only. |
| D12 | nit | `internal/config/config.go` `envFloat`; `cmd/sanctum/main.go:146-148` | `float64(hours) * float64(time.Hour)` overflows `time.Duration` for very large values (implementation-defined conversion) and truncates tiny positives to 0, silently disabling the alert. Operator-only input. → Clamp to a sane range (e.g. 1 minute to 1 year). |
| D13 | nit | `deploy/unraid.env.example:` `SANCTUM_BIND_IP=0.0.0.0`; `deploy/unraid-template.xml` port mapping | Constraint 7 says the compose file binds the published port explicitly. The Unraid example and template publish on all host interfaces. LAN-only is then an operator/firewall property, not a config one. → Document binding to the server's LAN IP in RUNBOOK. Also `docker-compose.yml` header still says "not published to a registry" (stale). |
| D14 | nit | `internal/httpapi/server.go` `handleUnlock`/`handleProvision` | By design, whoever reaches a brand-new vault's unlock page (then the provision form) first owns it; type-twice protects typos, not claim races. → Say in RUNBOOK: do first-run setup before exposing the port to the LAN, or bind to localhost for setup. |

### Checked and found sound (no finding)

- **Notifier (`url.go`):** URL never logged or echoed (`Describe()` is kind+host without userinfo/path;
  parse and network errors are rewritten without the URL; `-notify-test` prints only those);
  redirects refused (`ErrUseLastResponse`), TLS verification left at defaults, 10 s timeout, response
  drained through a 64 KiB `LimitReader`. Nothing backup-controlled reaches the URL or headers;
  `Title` goes through `headerSafe`; ntfy body is plain text, Discord/Slack/webhook use `json.Marshal`.
  Intent text comes from fixed strings, timestamps, counts, and the authenticated owner's own label.
- **Update check:** fixed API URL, redirects refused, 1 MiB read cap, drafts/prereleases ignored, tag
  must parse as semver, link restricted to `https://github.com/`; it only reports (grep: no
  download/exec/docker use). Banner rendered via `html/template`.
- **Upload handler:** auth first; early 413 on declared length; `MaxBytesReader` bounds chunked and
  lying clients; `stageInput` adds a second `LimitReader` plus a one-byte probe; staging file removed on
  every error path (`stageInput` defer + `defer os.Remove` in `IngestReader`); non-file parts skipped;
  `FileName()` is already `Base`-ed and only stored as metadata.
- **Setup/auth flow:** `FirstRun` cannot be forced by a remote caller (it reads the sealed-index files
  on disk; the only way to change them is filesystem access or the D02 crash state); provision is
  refused once an owner exists; type-twice checks run before any state change; F04 sentinel path
  untouched; `/lock` requires a session.
- **Container v2:** `header.go` accepts exactly versions 1 and 2, everything else still fails closed;
  nothing in the Go source reads `settings.json`; the `%w: %w` wrapping makes `errors.Is(err,
  ErrUnsupportedVer)` work.
- **Container/compose/template:** both `FROM` lines digest-pinned, `USER 65532`, image-level
  `HEALTHCHECK`, compose `read_only`, `cap_drop: ALL`, `no-new-privileges`, memory/CPU limits, bounded
  logs, default bind `127.0.0.1`; template masks the notification URL, is not privileged, passes the
  same hardening flags. Config defaults make the template's missing `SANCTUM_*_DIR` env vars safe.
- **Release workflow:** top-level `contents: read`, job-level elevation only where needed, version
  derived from the tag via env (no expression injection), tag pattern strict, Trivy gate exits 1 on
  HIGH/CRITICAL, non-root assertion, provenance/SBOM/attestation wired. (Findings D04–D06 above.)
- **Host scripts:** dispatcher passes event text only as quoted option values to `notify`, never to
  `eval`/`sh -c`; update script quotes consistently, takes a flock, refuses a dirty tree and
  non-fast-forward tags, and rolls back. `smoke-live.sh` refuses `rm -rf` unless the directory
  basename starts with `sanctum-smoke`.

### Not covered / human-only residuals

- **Image build and `docker inspect` not run here** (no Docker on the audit host); relies on CI
  success on the pre-release tip and the 2026-11-09 live smoke.
- **`go test -race` not run** (Windows host without cgo); CI runs it.
- **`release.yml` has never executed**; D04–D06 are from reading, and the first tag push is its first test.
  Do a dry run on a throwaway tag in a fork or with `act`.
- **`sanctum-update.sh` and the dispatcher were read, not executed** (no jq/docker/shellcheck on the
  audit host).
- Real-hardware power-loss and OOM behaviour for D01/D02 (the PoCs simulate the on-disk states).
- Off-lens, one line: `ReadTimeout`/`WriteTimeout` of 10 min means a 512 MiB upload or restore needs
  about 0.85 MB/s sustained; the progress-UI backlog item will want this revisited.

### Verdict: **NO-GO for v0.1.0 as it stands; GO once D01 and D02 are fixed and re-verified**

Both blockers are in the vault's own index persistence and unlock path, are small to fix, and each has a
failing PoC to turn into a regression test. D03–D09 should be fixed in the same release if cheap
(D03, D05 and D07 are one-line to few-line changes); D04/D06 must be settled before the first tag push
because that push is `release.yml`'s first run. D10–D14 can follow in a patch release. After fixes, re-run
this pass's checks (vet, tests, guards, govulncheck) plus the new regression tests.

### Resolution (2026-11-10, D01–D09 applied; D10–D14 left for a patch release; not committed)

| ID | Fix | Verified by |
|---|---|---|
| D01 | New `internal/vault/checkpoint.go`: while unlocked, a goroutine seals the index every 10 s when its content hash changed, and immediately after each ingest (`ingest.Options.OnCommit`). Same AES-GCM seal and key handling as `Lock` (key still never at rest). `Lock` stops the loop without waiting on it (no deadlock). The first checkpoint also writes the first seal, so a vault no longer reverts to first-run after a crash. | `TestCheckpoint_SurvivesUncleanStop_D01` (checkpoint, unchanged index not rewritten, second `Vault` on the same dirs unlocks and still has the owner) |
| D02 | `unsealOrOpen` allows a fresh index only when no seal generation exists (`SealExists` now covers `index.sealed`, `.tmp`, `.prev`). `UnsealFile` tries current → unpromoted `.tmp` → `.prev`, each authenticated; a truncated `.tmp` falls back to `.prev`. Stale "next-run recovery" comment now true. | `TestUnlock_MissingPrimaryWithPrev_DoesNotFailOpen_D02` (wrong passphrase refused, right one recovers), `TestUnsealFile_RecoversFromTmpWhenPrimaryMissing_D02` |
| D03 | `clientIP` returns the TCP peer host only; `X-Forwarded-For` ignored. | `TestClientIP_IgnoresForwardedFor_D03`, `TestLimiter_NotBypassedByForwardedFor_D03` (50 rotated-header attempts → exactly 5 allowed) |
| D04 | `release.yml`: checkout with full history; refuses a tag whose commit is not an ancestor of `origin/main`; only the highest `v*` tag moves `:stable`. Still do: a repository ruleset restricting `v*` tag creation (GitHub setting, not code). | YAML parses; logic read only (workflow never run) |
| D05 | `aquasecurity/trivy-action` pinned to commit `ed142fd…` (v0.36.0) in `release.yml` and `ci.yml`. | grep; YAML parses |
| D06 | Build once, push by digest untagged; non-root guard and Trivy run against that digest; `:<version>`/`:stable` applied with `buildx imagetools create` only after both pass; attestation unchanged. | YAML parses; logic read only |
| D07 | New `.dockerignore` (`.git`, `.env*`, `*.tryst`, `inbox/`, `vault/`, `testdata/real/`, seal/manifest/state files, `bin/`, `deploy/`, `docs/`, `scripts/`, `*.md`). | Linux build still passes; **docker build not run here**, CI will exercise it |
| D08 | `sanctum-update.sh`: tags must match `^v[0-9]+\.[0-9]+\.[0-9]+$`; `--apply` requires `git verify-tag` (new default `REQUIRE_SIGNED=1`; `--check` only adds a note when unverifiable); `AUTO_APPLY=1` refuses to run without it; `emit` JSON-escapes every field. **Operator impact:** apply will refuse until the maintainer's signing key is in the host keyring and tags are signed, or `SANCTUM_UPDATE_REQUIRE_SIGNED=0` is set deliberately. | `bash -n`, `jesc` run against a string with `"` and `\`, tag regex run against sample tags; script not executed end to end |
| D09 | `ingest.Service` allows one ingest at a time (`stageSem`): a browser upload gets `ErrBusy` → HTTP 503 immediately; the inbox watcher waits its turn. | `TestIngestReader_UploadRefusedWhileAnotherIngestRuns_D09` |

Re-run after the fixes: `gofmt -l` clean, `go vet ./...` clean, `go test -count=1 ./...` all 15 packages
`ok`, `scripts/guards.sh all` green, linux static build OK. Not re-run: `-race` (no cgo on this host; CI
runs it, and the checkpoint goroutine is the new concurrency to watch), image build, `release.yml`.

**Updated verdict: GO for v0.1.0 once CI (including `-race` and the image build) is green on the commit
that carries these changes and a throwaway tag has exercised `release.yml`.** D10–D14 remain open as nits.

---

## Consolidated go/no-go (all Phase 3 passes)

| Pass | Lens | Verdict |
|---|---|---|
| 001 | crypto + secrets/storage/logging | GO (post fixes F01–F07) |
| 002 | delta-audit + verification | GO |
| 003 | dependencies & licenses | GO |
| 004 | network & exposed surface | GO |
| 005 | input & injection | GO |
| 006 | build hardening | GO |
| 007 | UI / accessibility | GO |

**Release verdict: GO**, conditional on the four human-only smokes carried
forward into M6 deploy-to-Unraid:

1. Compose without the `tmpfs:` stanza → expect `ErrTmpDirNotTmpfs` at
   startup (F01 runtime backstop).
2. `curl -F file=@600MB.bin` against a running server → expect fast 413,
   no RSS spike (F02 real-scale check). *Live run 2026-11-09 found the original handler staged the
   refused body on tmpfs (648 MiB peak); fixed by rejecting on Content-Length and streaming the part.*
3. Hand-edit `manifest.json` KDF salt after a real seal exists → expect
   `ErrManifestOutOfBand` (F05).
4. `govulncheck ./...` and image-level trivy scan in CI on every release.

**Accepted residual risks:**

- Go compiler may retain register/stack copies of the runtime key that
  `Key.Zero()` cannot reach.
- Rate limiter is per-IP with arbitrary-bucket eviction at 4096 — LAN
  posture makes this acceptable.
- Backup passwords sit cleartext in the sealed SQLite index while
  unlocked (on the F01-guarded tmpfs). Required by D-13/F18.
- No CSP / X-Frame-Options today — LAN-only + static templates +
  SameSite=Strict cookies make this low-impact.
- Watcher does not check inbox entries for symlink escape — inbox is
  `:ro` and any followed link fails TRYSTBK1 parse harmlessly.

---

### Fix log

- **F01 — applied 2026-08-23.** `vault.Paths.AllowNonTmpfsTmpDir` opt-in
  added; `Vault.New` requires TmpDir, rejects `TmpDir == VaultDir`, and on
  Linux runs a `statfs` check accepting only `tmpfs`/`ramfs` magics.
  `ingest.Options.TmpDir` is now required (silent `os.TempDir()` fallback
  removed). Plumbed through `Config.AllowNonTmpfsTmpDir` +
  `SANCTUM_ALLOW_NONTMPFS_TMPDIR` env and `cmd/sanctum/main.go`. Test
  call sites updated with the opt-in (t.TempDir is real fs). New unit
  tests: `TestNew_RejectsEmptyTmpDir`, `TestNew_RejectsTmpDirEqualToVaultDir`.
  **Verify pending:** `go test ./...` and a compose-without-tmpfs smoke —
  Sanctum should fail to start with `ErrTmpDirNotTmpfs` rather than
  silently writing to /tmp on the array.
- **F07 — applied 2026-08-23.** `Key.Bytes()` now returns a fresh 32-byte
  copy instead of an aliasing slice into the Key's storage — the pre-F07
  behaviour let a caller stash the slice past `Zero()` and silently read
  wiped bytes. The old aliasing behaviour is preserved as `Key.BytesUnsafe()`
  for hot paths that need it (none in Sanctum today). Both production
  callers (`vault.Lock` seal write, `unsealOrOpen` unseal read) already
  use `Bytes()` synchronously; the copy is trivial next to the AES/GCM
  work that consumes it. New tests: `TestKey_Bytes_ReturnsCopy_F07`
  (proves Bytes() copies AND survives Zero), `TestKey_BytesUnsafe_Aliases_F07`
  (guards the escape-hatch contract).
  **Verify pending:** `go test ./internal/vaultkey/... ./internal/vault/...`.
- **F05 — applied 2026-08-23.** Seal format bumped to v2 (Sanctum is
  pre-M6, no live seal on the array to migrate). New header layout:
  `magic|version|reserved|bindHash(32)|nonce(12)|ct+tag` — 52-byte header
  instead of 20. `SealBytes`/`UnsealBytes`/`SealFile`/`UnsealFile` all
  take a new `binding []byte` parameter; the SHA-256 of that blob is
  stored in the header, checked BEFORE the AEAD attempt via
  `subtle.ConstantTimeCompare`, and also bound into GCM AAD (so an
  attacker who rewrote the header hash to match still fails GCM auth).
  New `ErrSealManifestOutOfBand` sentinel + vault-layer
  `ErrManifestOutOfBand`; the vault's `unsealOrOpen` maps the low-level
  error to the top-level one so `Vault.Unlock` returns a distinct signal.
  `.prev` fallback short-circuits on `ErrSealManifestOutOfBand` — both
  generations were written under the same manifest, so retrying the
  older one is pointless. New `internal/vault/binding.go` produces a
  deterministic hand-rolled encoding of the KDF stanza (versioned
  prefix `SNBIND-01`) instead of relying on `json.Marshal`'s stable-but-
  not-guaranteed field ordering. All test call sites updated to pass
  `nil` binding for isolation tests, plus new tests
  `TestSealBytes_ManifestBindingF05` and
  `TestUnlock_TamperedManifestSurfacesOutOfBand_F05`.
  **Verify pending:** `go test ./internal/index/... ./internal/vault/...`
  plus a manual smoke: after a real unlock+lock cycle, flip a byte of
  `manifest.json`'s KDF salt and confirm the next unlock returns
  `ErrManifestOutOfBand` (not `ErrBadPassphrase`).
- **F04 — applied 2026-08-23.** Login handler restructured so the
  "unknown user" and "wrong password" paths run the same three
  operations in the same order: DB lookup, PBKDF2 with matching iteration
  count, `subtle.ConstantTimeCompare`. The miss path substitutes a
  `sentinelOwnerAuth()` (fixed non-zero 16-byte salt, `ownerLoginIters`,
  32 zero bytes as the "hash") so PBKDF2 and the compare execute
  identically to the hit path; the Boolean `found` from the fetch is
  what actually gates the response, so the compare's result on the miss
  path is discarded — only its runtime matters. `ownerLoginIters` is
  now a shared constant so a bump in the provisioning path moves the
  sentinel with it and the symmetry survives. Removing the old
  `"dummy-salt-16bytes!"` literal collaterally closes **F06** (label
  was 19 bytes, not 16).
  **Verify pending:** re-run existing `/login` tests
  (`TestLogin_WrongPassword`, `TestLogin_UnknownUser`) — both should
  still return the neutral 200 "Invalid credentials" page. Optional:
  micro-benchmark the two paths and confirm they land within a few %
  of each other under load.
- **F03 — applied 2026-08-23.** Added
  `vaultkey.ValidateProduction(Params) error` with the OWASP-2023 floor
  constants (`MinProductionTime=3`, `MinProductionMemoryKiB=64*1024`,
  `MinProductionParallel=1`) and a distinct `ErrKDFBelowProductionFloor`
  sentinel. `Vault.Unlock` now calls `ValidateProduction` on
  `v.manifest.KDF` before deriving; a failure logs the offending KDF
  stanza and returns the wrapped error without touching the passphrase.
  Escape hatch is `vault.Options.AllowInsecureKDF` — used by
  `newTestVault` and the httpapi e2e (which run `vaultkey.TestParams`).
  `IsInsecureForTest`'s docstring rewritten to stop claiming a production
  role. New tests: `TestDefaultParams_MeetsProductionFloor`,
  `TestValidateProduction_RejectsTestParams`,
  `TestValidateProduction_BoundaryPerAxis`,
  `TestUnlock_RejectsBelowProductionFloor_F03`.
  **Verify pending:** `go test ./internal/vaultkey/... ./internal/vault/...`
  plus a manual smoke — edit a production manifest's `t` to `1` and
  confirm Unlock refuses with the new error rather than deriving anyway.
- **F02 — applied 2026-08-23.** `/upload` now wraps `r.Body` in
  `http.MaxBytesReader(w, r.Body, uploadBodyLimit)` (MaxBackupBytes + 64
  KiB slack) before calling `ParseMultipartForm(uploadInMemoryLimit)`;
  the in-memory threshold dropped from 1 GiB → 16 MiB (the rest spills
  to TmpDir, which F01 forces onto tmpfs). Body-too-large is mapped to
  413 via a new `isBodyTooLarge` helper covering both
  `http.ErrRequestBodyTooLarge` and `*http.MaxBytesError`. New test:
  `TestUpload_OversizeBodyRejectedWith413_F02` (shrinks the limits at
  test-time to avoid moving 512 MiB through httptest).
  **Verify pending:** the new test under `go test ./internal/httpapi/...`,
  plus a manual curl of a 600 MiB body to confirm the 413 lands fast and
  RSS does not spike.
