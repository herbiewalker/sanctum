# Sanctum — Architecture

> **Status:** Design intent (2026-08-22). Nothing below is implemented yet beyond the M0 scaffold —
> this describes the shape the roadmap builds toward. Update it in the same change that makes it
> stale (principle 3).

## Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Language | Go (see [SETUP.md](../SETUP.md) for the pin) | static binary → distroless, non-root, read-only rootfs nearly free (D-6) |
| Crypto | `tink-go` `AesGcmHkdfStreaming` + `golang.org/x/crypto/pbkdf2` | official implementation of the exact primitive Tryst writes; never hand-rolled (D-6) |
| Index | SQLite on tmpfs, sealed to the array as a Tink blob | keeps the static binary (no cgo/SQLCipher) while leaving nothing readable at rest (D-5) |
| HTTP | stdlib `net/http` | no framework; smallest dependency surface to audit |
| Build | `go build`, `make`, multi-stage `Dockerfile` | one command from clean checkout to green |
| Deploy | `docker compose` on Unraid | matches the existing `unraid_immich_dockercompose` idiom |

## Shape

```
   phone                     Unraid host                          Sanctum container
 ┌────────┐            ┌──────────────────┐        ┌──────────────────────────────────────┐
 │ Tryst  │  export    │  /mnt/user/…     │        │                                      │
 │  app   │ ─────────► │    inbox/        │ ──────►│  watcher ─┐                          │
 └────────┘  share     └──────────────────┘  bind  │           ├─► INGEST PIPELINE        │
   (no network — D-1)   Syncthing / SMB / SAF      │  HTTP  ───┘   ├ parse header         │
                                                   │  upload       ├ sha256               │
   browser ───────────────────────────────────────►│               ├ TRIAL DECRYPT ◄──────┼── runtime key
   (LAN only — D-12)                               │               ├ read data.json meta  │   (RAM only)
                                                   │               └ store + index        │
                                                   │                      │               │
                                                   │        ┌─────────────┴────────────┐  │
                                                   │        ▼                          ▼  │
                                                   │   blob store                  index   │
                                                   │  (opaque TRYSTBK1,          (SQLite   │
                                                   │   immutable, sha256)        on tmpfs) │
                                                   │        │                          │   │
                                                   └────────┼──────────────────────────┼───┘
                                                            ▼                          ▼
                                                   /mnt/user/appdata/sanctum/    …/index.sealed
                                                        vault/<owner>/…          (Tink-encrypted)

                          ── everything the array ever sees is ciphertext ──
```

## Component responsibilities

| Component | Responsibility | Talks to |
|-----------|----------------|----------|
| `cmd/sanctum` | wiring, config load, signal handling, graceful shutdown | everything |
| `internal/config` | env-only config (12-Factor III); no secrets, ever | — |
| `internal/vaultkey` | passphrase → runtime key; holds it in RAM; zeroes on lock/SIGTERM | sealer, blobstore |
| `internal/trystbk` | `TRYSTBK1` reader: header parse, PBKDF2, streaming AEAD, ZIP walk | tink-go |
| `internal/ingest` | the one pipeline: verify → hash → trial-decrypt → store → index | trystbk, blobstore, index |
| `internal/blobstore` | immutable owner-scoped blob storage + SHA-256 manifest | filesystem |
| `internal/index` | SQLite on tmpfs; seal/unseal to the array | vaultkey, filesystem |
| `internal/watcher` | inbox directory watch, debounce, hand off to ingest | ingest |
| `internal/httpapi` | unlock page, upload, status, restore, `/healthz` | ingest, index, blobstore |
| `internal/retention` | scheduled prune + staleness evaluation | index, notifier |
| `internal/notify` | Unraid notification channel (see O-2) | host |

## The two states

Sanctum is a state machine with exactly two states, and the distinction is the security model:

- **LOCKED** (always the state after start). Serves `/healthz` and the unlock page. Nothing else —
  no ingest, no listing, no status detail. The watcher does not run. The runtime key does not exist.
- **UNLOCKED.** Passphrase accepted, runtime key derived and held in memory only. Index unsealed onto
  tmpfs. Watcher, ingest, retention, and the full API are live.

Transitions: start → LOCKED. unlock → UNLOCKED. SIGTERM / explicit lock / restart → LOCKED, key
zeroed, index re-sealed. **There is no path that persists the key across a restart** (D-4).

## Critical data flows

**1 · Ingest (the path that matters most).** A file appears in `inbox/` or arrives by upload →
read the 29-byte cleartext header, reject on bad magic/version, bound the iteration count →
SHA-256 the whole file → **trial-decrypt** the AEAD stream with the owner's backup password — trying each in the per-owner set (D-13)
→ open the inner ZIP, read `data.json`'s `schemaVersion` and per-table counts, validate every entry
name against Zip-Slip → if all of that passes, move the original bytes into the blob store unchanged
and write an index row. **Only the original ciphertext is ever persisted.** The decrypted stream is
consumed and discarded; nothing decrypted is written anywhere but tmpfs, and only transiently.

*Trust boundary:* the entire inbox is untrusted input. Anything that can write to that share can
hand Sanctum a hostile file — a crafted header (huge iteration count → DoS, N9), a Zip-Slip entry
name (N10), a zip bomb, a truncated stream. Every one of those is a rejection with a log line, not
a crash.

**2 · Restore.** Look up the version → re-verify SHA-256 against the manifest → stream the stored
bytes out unchanged. Restore does **not** decrypt: the file that leaves is byte-identical to the file
Tryst wrote, and the owner's backup password opens it in Tryst exactly as before (N8).

**3 · Unlock.** Passphrase → KDF → runtime key in memory → unseal the index blob onto tmpfs → start
the watcher. A wrong passphrase fails on AEAD authentication of the index seal, which is the same
"wrong password fails cleanly" property `TRYSTBK1` itself has.

## Cross-cutting concerns

- **Config** comes from the environment only (12-Factor III), and contains **no secrets** — paths,
  ports, thresholds, retention counts. The passphrase is never config; it is typed at unlock (D-4).
- **Logging** goes to stdout/stderr, structured. It must never contain: the passphrase, any derived
  key, any backup password, partner names, or encounter content (N15). Log the *fact* of an ingest
  and its hash — never its contents. Given D-10's discretion rationale, keep subjects and log lines
  neutral too.
- **Errors** on the ingest path are always "reject and keep the previous good state". An ingest never
  half-writes: the blob store move is the last step, after every check has passed.
- **Persistence & migrations** → [DATA_MODEL.md](DATA_MODEL.md). The index schema is versioned from
  v1 and the blob layout is versioned independently of it.
- **Time** matters for staleness (F9) and retention (F8) — use UTC internally, and never trust a
  timestamp from inside a backup for retention decisions.
