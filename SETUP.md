# Sanctum — Environment Setup

> Everything needed to take a **clean checkout to a green build**, including the traps. Principle 8:
> write the **fix**, not just the name of the trap. Update this the moment something burns time —
> same change, same commit.

## Toolchain

| Tool | Version | Install / where |
|------|---------|-----------------|
| Go | **1.26.10** (the `go` directive in `go.mod` is the source of truth; CI reads it via `go-version-file`) | `winget install --id GoLang.Go` |
| Git for Windows | any recent | provides the Git Bash the guards need |
| Docker | only for image work | **not installed on this dev box** — see the gap list below |
| trivy | CI only | runs in the `image` job; not needed locally |

## Environment variables / local config

- Nothing is required to build or test — `config.Load()` has working defaults for everything.
- `.env` (from `.env.example`) is only needed to run `docker compose`. **Gitignored, never committed.**
- **There is no environment variable that unlocks the vault.** The passphrase is typed by a human
  after every container start and lives only in process memory (hard constraint 3 / ADR D-4). If you
  find yourself wanting to add `SANCTUM_PASSPHRASE`, that is the constraint working as intended.

## Bootstrap (one command)

```powershell
.\bootstrap.ps1
```

Verify — it should print `BOOTSTRAP GREEN`. Then:

```powershell
$env:SANCTUM_ADDR = "127.0.0.1:8080"; .\bin\sanctum.exe
```

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok","state":"locked","uptime":"0s"}
```

On Linux or in CI, `make check` does the same thing.

## Platform gotchas (trap → fix)

- **There is no `make` in Git Bash on Windows.** `make check` fails with "command not found" on the
  dev box even though it works in CI. → Use `.\bootstrap.ps1`, which runs the same steps. The
  `Makefile` is for CI and Linux. Both call `scripts/guards.sh` so the guards cannot drift apart.

- **There is no `python` on this box either** (the Microsoft Store alias shim intercepts it and
  prints an install prompt instead of erroring usefully). → Do not write build tooling that assumes
  Python. Bash and PowerShell only.

- **`go install` does not refresh `PATH` in an already-open shell.** After
  `winget install --id GoLang.Go`, `go version` still reports "command not found" in the shell you
  ran it from. → Open a new shell, or let `bootstrap.ps1` handle it — it falls back to
  `$env:ProgramFiles\Go\bin\go.exe` and prepends it to `PATH` for the current run.

- **`go test -race` needs cgo, and there is no C toolchain on a stock Windows box.** → The race
  detector runs in CI on Linux only. `bootstrap.ps1` runs `go test` without `-race` deliberately;
  this is a known, accepted gap, not an oversight. Do not "fix" it by dropping `-race` from CI.

- **`kill -TERM` from Git Bash does not deliver a real SIGTERM to a native Windows binary.** It
  terminates the process (exit 143) without running Go's signal handler, so
  **graceful shutdown cannot be verified on Windows** — the shutdown log lines never appear and it
  looks like the handler is broken when it is not. → Verify graceful shutdown in the container with
  `docker stop` and check for `shutdown complete` in the logs. Tracked as an M0 exit item (N11).
  This is lesson L19 in miniature: developing Linux-target code on Windows validates syntax, not
  behaviour.

- **Heredocs of more than ~100 lines are unreliable through the Bash tool here** — they fail with
  `unexpected EOF while looking for matching quote`. → Write long files directly rather than
  shelling out to `cat > file <<'EOF'`.

- **Windows line endings would break the container.** `.gitattributes` forces `eol=lf` for
  everything except `*.ps1`. `scripts/guards.sh` and the `Dockerfile` **must** be LF or they fail at
  runtime on Linux with `bad interpreter: \r`. → Do not override `core.autocrlf` for this repo.

- **PowerShell 5.1's `Set-Content`/`Out-File -Encoding utf8` writes a UTF-8 BOM.** A BOM silently
  breaks parsers (it cost a full session on Tryst when detekt stopped recognising Kotlin
  annotations). → Write files with
  `[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))` and
  normalise `\r\n` → `\n`. Verify with `[System.IO.File]::ReadAllBytes($path)[0..2]` — it must not
  be `EF BB BF`.

- **Do not pass strings containing `"` to native exes from PS 5.1** (e.g. `git commit -m`) — the
  re-quoting mangles them into separate arguments. → Write the message to a file and use
  `git commit -F`.

## Known toolchain gaps on this dev box

Honest list; each is a real limit on what can be verified locally (principle 11 — a green local run
is a lower rung than a real one).

| Gap | Consequence | Where it gets verified instead |
|-----|-------------|--------------------------------|
| No Docker | cannot build the image, run `make image-checks`, or validate `docker compose config` locally | CI's `image` job — **green as of 2026-08-22**, so the image is built and asserted on every push |
| No `make` | `make` targets are CI/Linux only | CI; `bootstrap.ps1` locally |
| No C toolchain | no `-race` locally | CI's `go` job |
| Windows signals | graceful shutdown (N11) unverifiable | `docker stop` on the real box, M0 exit |
| No real `.tryst` fixture in-repo (by design — hard constraint 4) | crypto interop unproven | M1 exit, against a genuine backup from your own Tryst phone |

## IDE / editor

- Open the repo root; the Go module is rooted there.
- `.editorconfig` handles indentation (tabs for Go, 2-space elsewhere). Let it.
