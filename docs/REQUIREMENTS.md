# Sanctum — Requirements

> **Status:** v1 draft (2026-08-22), from the Phase 0 kickoff. Tracks `CLAUDE.md`'s hard constraints
> as testable NFRs.

## Problem & users

- **Problem:** Tryst holds the owner's entire intimacy history on a single Android phone, encrypted
  under a **device-bound, non-exportable** Keystore key. There is no cloud backup by design (Tryst
  D-1/D-3). The only safety net is a manually exported `TRYSTBK1` file that the owner has to
  remember to make, and then remember where they put. A lost or dead phone with a stale export is
  total data loss of years of records.
- **Users:** the owner (one person, today). Later, a partner who runs their own Tryst instance and
  wants their own separate space plus an opt-in shared picture.
- **Success criteria (v1):**
  1. A `.tryst` file dropped in the inbox is ingested, verified, and retained without any manual step.
  2. Every retained backup has been **proven openable** by trial decrypt, not merely stored.
  3. Restoring a backup returns a **byte-identical** file to what Tryst exported.
  4. The owner is told when the newest backup goes stale, and does not have to remember to check.
  5. Pulling any array disk, browsing any share, or restoring the Unraid appdata backup elsewhere
     yields **ciphertext only**.
  6. Tryst's `checkNoNetworkRelease` still passes, unchanged, on an untouched Tryst repo.

## In scope (v1)

- **R1 — Ingest.** Watch a drop folder; accept browser uploads. Both feed one pipeline.
- **R2 — Verify.** Parse the `TRYSTBK1` header, record SHA-256, and **trial-decrypt** to prove the
  container opens and the ZIP within is well-formed.
- **R3 — Retain.** Per-owner versioned history, immutable blobs, configurable retention and prune.
- **R4 — Alert.** Notify when an owner's newest backup exceeds a staleness threshold.
- **R5 — Restore.** Hand back any retained version as a byte-identical `.tryst` file.

## Non-goals (v1)

> The single most effective scope-creep brake.

- **Viewing encounter data.** No browsing, no timeline, no stats, no photos. The vault verifies that
  the data is intact and openable; it does not show it. *(v2 — and O-5 may change how.)*
- **Partner sharing** of any kind, merged or aggregate. The data model supports owners (D-8); the
  feature is not built. *(v2+, gated on D-9's own ADR and a threat-model revision.)*
- **Any change to the Tryst app** — no sidecar app, no network permission, no protocol. (D-1.)
- **Internet exposure** — no port forward, no public DNS, no ACME, no reverse proxy. (D-12.)
- **Transport from the phone.** Syncthing/SMB/SAF move the file; Sanctum only receives it.
- **Mobile push, e-mail, or any outbound network** beyond the local Unraid notification channel.
- **Multi-tenancy** past two owners. This is a household service, not a product.
- **Importing non-Tryst formats.** Tryst's own CSV importer already covers that, on-device.
- **Backing up Sanctum itself.** The blobs are already copies; Sanctum is not the system of record.

## Functional requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| F1 | Watch a configured inbox directory and ingest any new `TRYSTBK1` file | Must |
| F2 | Accept a `TRYSTBK1` upload over HTTP from the LAN web UI | Must |
| F3 | Validate magic, format version, salt, and the PBKDF2 iteration count (bounded 100k–5M) | Must |
| F4 | Trial-decrypt each ingest and confirm the inner ZIP lists the expected entries | Must |
| F5 | Record SHA-256 at ingest; re-verify on every read | Must |
| F6 | Store blobs immutably, owner-scoped, never rewritten in place | Must |
| F7 | Record `schemaVersion` from `data.json` and per-table row counts in the index | Must |
| F8 | Apply a configurable retention policy and prune beyond it | Must |
| F9 | Emit a staleness alert when an owner's newest backup exceeds the threshold | Must |
| F10 | Serve an exact byte-identical restore of any retained version | Must |
| F11 | Boot locked; expose only unlock + `/healthz` until a human unlocks | Must |
| F12 | Rebuild the index from stored blobs alone (the D-5 recovery path) | Must |
| F13 | Refuse a duplicate ingest (same SHA-256) without creating a new version | Should |
| F14 | Report per-owner vault status: newest backup, count, total size, last verify | Should |
| F15 | Re-verify all stored blobs on a schedule, not only on read | Could |
| F16 | Owner login gates access to that owner's backups (D-14). Vault unlock is a separate credential | Must |
| F17 | Owner can manage the per-backup password set (D-13): add, list labels, delete. Add is the only mutation on an existing entry | Must |
| F18 | Ingest tries every password in the owner's set and records the winner on the backup row | Must |
| F19 | Media entries are counted from the ZIP central directory only (D-15); no `media/*` entry is decrypted in v1 | Must |

## Non-functional requirements

> The hard constraints from `CLAUDE.md` as testable statements.

| ID | Requirement | How it is verified |
|----|-------------|--------------------|
| N1 | No plaintext user data is ever written outside tmpfs | `make guard-no-plaintext` — full ingest cycle, then scan the array dir for readable ZIP/JSON |
| N2 | No key material at rest in image, compose, `.env`, or appdata | `make guard-no-secrets` + trivy secret scan on the final image (CI) |
| N3 | Container runs non-root, read-only rootfs, all caps dropped | CI: `docker inspect` user check; compose asserts `read_only`, `cap_drop: [ALL]` |
| N4 | Base image pinned by digest, never `:latest` | CI: `Dockerfile` grep guard |
| N5 | No CRITICAL/HIGH CVEs in the shipped image | CI: trivy vuln scan, `exit-code: 1` |
| N6 | A tampered blob fails verification | Test: flip one byte → SHA mismatch **and** AEAD failure (principle 12 — forced, not read) |
| N7 | A wrong password fails cleanly, without a crash or a partial write | Test: deliberate wrong-password ingest |
| N8 | Restore is byte-identical to the original export | Test: SHA-256 of restored file == SHA-256 at ingest |
| N9 | An absurd iteration count cannot hang the service | Test: header claiming `Int.MAX_VALUE` is rejected by the bound, not attempted |
| N10 | A crafted blob cannot write outside the storage dir (Zip-Slip) | Test: ZIP entries named `../x` and `a/b/c` are rejected |
| N11 | SIGTERM shuts down gracefully and zeroes the runtime key | Test + manual `docker stop` observation |
| N12 | Only the one intended port is published; no host network | CI: `docker compose config` assertion |
| N13 | Tryst remains unmodified | Review; `checkNoNetworkRelease` green on an untouched Tryst checkout |
| N14 | Memory and CPU limits are set so Sanctum cannot starve the Unraid host | compose `deploy.resources`; asserted in `docker compose config` check |
| N15 | Logs never contain passwords, key material, partner names, or encounter content | Test: log scrape during a full ingest of a real backup |
| N16 | The vault-unlock endpoint is rate-limited (D-14) — small guessing budget per unit time, per source IP | Test: a burst of wrong attempts is rejected before the KDF work is done |
| N17 | Owner-login sessions do not survive a re-lock: after `LOCKED → UNLOCKED → LOCKED`, previously-issued session cookies must not authenticate anything | Test: unlock → issue cookie → re-lock → attempt to use cookie → expect rejection |
| N18 | Session cookies are `HttpOnly` + `Secure` + `SameSite=Strict`, and their storage lives on tmpfs | Test: header assertion; guard that the session store path resolves inside the configured tmpfs |
| N19 | No `media/*` ZIP entry is decrypted in v1 (D-15) | Test: instrument the ZIP reader; a `Read()` on any entry under `media/` fails the test |
