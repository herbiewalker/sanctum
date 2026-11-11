# Sanctum — Decision Log (ADRs)

> **Status:** Live — D-1…D-17 from the Phase 0 kickoff interview (2026-08-22). Newest at the bottom.
> Never delete an ADR; supersede it with a new one.

Format: Nygard-style, trimmed. Context → Decision → Alternatives rejected → Consequences.

---

## D-1 — Tryst is not modified; backups arrive as files
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** Tryst's identity rests on three foundational ADRs — its `D-1` (no accounts, no sync,
  no second device), `D-2` (threat model protects against *any* network leakage), `D-3` (no
  `INTERNET` permission) — the last enforced by the `checkNoNetworkRelease` build gate, which is the
  DevPlaybook's own flagship example of principle 1 (lesson L2). Every F-Droid user sees the empty
  permission list. Sanctum needs backups from the phone.
- **Decision:** Sanctum ingests `TRYSTBK1` **files**. Transport is somebody else's problem: a
  watched drop folder fed by Syncthing/SMB/SAF, or a browser upload. Tryst gets **zero** changes.
- **Alternatives considered:**
  - *Sidecar Android app* with its own `INTERNET` permission, reading backups via SAF. Preserves
    Tryst's guarantee and gives one-tap UX — but it is a second app to build, audit, and distribute,
    for a transport problem Syncthing already solves. **Deferred, not rejected** — if push-button
    sync becomes the bottleneck, this is the answer, and Sanctum's HTTP ingest API is already the
    seam it would talk to.
  - *Add network to Tryst.* Overturns Tryst's D-1/D-2/D-3, invalidates its 12-pass audit (principle
    9), and changes what every F-Droid user sees. A one-way door on the app's identity, for no
    capability Sanctum cannot get another way. **Rejected.**
- **Consequences:** Ingest is asynchronous and best-effort; Sanctum can never *pull*, only receive.
  Staleness detection (D-11) therefore matters more, because nothing guarantees a backup ever
  arrives. Costs nothing in Tryst's audit posture — which is the point.

---

## D-2 — The adversary is the LAN, not the root shell
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** "As secure as possible so no one else can get the data even with local access" needs a
  definition of *who*. The owner clarified: other people on the LAN — family, guests, curious
  children — plus tampering with stored backups.
- **Decision:** In scope: anyone else on the LAN reaching the service; family browsing SMB shares or
  the Unraid GUI; tampering with stored blobs; a lost or RMA'd array disk; an Unraid appdata backup
  walking offsite. Out of scope, **accepted residual**: an adversary with root on the Unraid host
  while the vault is unlocked.
- **Alternatives considered:** *Defend against root-at-runtime.* Impossible for any design where the
  service can read the data — root reads process memory and takes the key. Claiming otherwise would
  be security theatre. **Rejected as unachievable, not as unimportant.**
- **Consequences:** Every decision below optimizes for the in-scope set. Physical possession of a
  running, unlocked box is a total loss; possession of a powered-off box, or of any single disk,
  yields ciphertext only. Recorded in `THREAT_MODEL.md` as R1.

---

## D-3 — Sanctum can decrypt; it is not a zero-knowledge vault
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** A pure opaque-blob vault is strictly safer, but can never show anything — which
  forecloses the reason the project exists (a shared picture for two partners).
- **Decision:** Sanctum holds the per-backup passwords and can decrypt. Confidentiality comes from
  D-4 (key never at rest) and D-5 (no plaintext at rest), not from ignorance.
- **Alternatives considered:**
  - *Zero-knowledge vault.* Safest; kills the product.
  - *Decrypt in the browser* — a WebCrypto reimplementation of AES-GCM-HKDF-Streaming + PBKDF2, so
    the server never sees a viewing key. Genuinely attractive, and a real middle path.
    **Deferred, not rejected** (see O-5). It does not solve v1's server-side need to trial-decrypt
    for verification, and reimplementing a streaming AEAD wire format in JS is exactly the crypto
    risk D-6 avoids.
- **Consequences:** Sanctum stores secrets that can open real intimacy data. That raises the stakes
  on D-4 and makes the unlock model load-bearing rather than a nicety.

---

## D-4 — The key never rests; manual unlock after every start
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** Given D-3, where the key lives *is* the security model.
- **Decision:** No passphrase or derived key material in the image, in `docker-compose.yml`, in a
  `.env` on the array, or in appdata. The container boots **locked** and serves nothing but the
  unlock page and `/healthz`; a human enters the passphrase and the runtime key exists only in
  process memory. Any restart re-locks.
- **Alternatives considered:**
  - *Key file on a separate/unassigned device.* Survives unattended reboots; beats disk theft and
    appdata backups; loses to anyone holding the whole box. **Rejected** — trades the strongest
    property for convenience the owner did not ask for.
  - *Passphrase in a gitignored `.env`.* Standard Docker practice, zero friction — and hands the key
    to anyone with file access to appdata or that share, which is precisely the D-2 adversary.
    **Rejected.**
- **Consequences:** An unattended 3am reboot leaves the vault locked until a human notices. This is
  deliberate. Scheduled work (retention, staleness alerts) can only run while unlocked, so the
  staleness alert must survive the vault being locked — it may report "locked since X", never
  contents. Adds a "did you re-unlock?" step to every Unraid reboot; goes in `RUNBOOK.md`.

---

## D-5 — Encrypted index on tmpfs, sealed to the array — not SQLCipher
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** The service needs a queryable index (owners, versions, hashes, timestamps, counts).
  Hard constraint 2 forbids any plaintext on the array.
- **Decision:** The SQLite index lives on **tmpfs** while unlocked and is sealed back to the array as
  a Tink-encrypted blob. The array never holds a readable index.
- **Alternatives considered:**
  - *SQLCipher* — symmetric with Tryst's own storage, and appealing for that reason. Requires cgo in
    Go, which forfeits the static binary and with it the distroless image, the trivial
    non-root/read-only-rootfs story, and cross-compilation. **Rejected**: the tmpfs approach gets the
    same property with less machinery, and at this data scale (order 10^3 encounters) an in-memory
    index is free.
  - *Plaintext index, arguing it is "only metadata".* Backup timestamps and per-owner counts are
    themselves sensitive here. **Rejected.**
- **Consequences:** Rebuild-index-from-blobs must exist and be tested — it is the recovery path if a
  seal is ever corrupted. Seal-on-write cadence becomes a real design question (durability vs churn).

---

## D-6 — Go, with tink-go for the crypto
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** Sanctum must read a container produced by Tink Java: PBKDF2-HMAC-SHA256 (600k
  iterations, count in the header, bounded 100k–5M on read) → `AesGcmHkdfStreaming`, 1 MiB segments,
  associated data `tryst-backup-v1`, wrapping a ZIP. Getting this wrong is silent data loss.
- **Decision:** Go, using **`tink-go`**'s official `AesGcmHkdfStreaming` and
  `golang.org/x/crypto/pbkdf2`. Single service, single language.
- **Alternatives considered:**
  - *Kotlin/JVM + Ktor*, reusing Tink Java — the exact library Tryst encrypts with, so wire
    compatibility would be guaranteed rather than tested for. This is DevPlaybook lesson L9, and a
    working JVM tool that reads `TRYSTBK1` already exists in the owner's local tools folder. **Rejected** on
    container weight, and because copying Tryst's `BackupCrypto.kt` would make Sanctum a GPL-3.0
    derivative (see D-7).
  - *Rust.* No official Tink. Would mean hand-implementing a streaming AEAD wire format against the
    most sensitive data the owner has. **Rejected** — this is the single place not to be clever.
  - *Python + FastAPI + tink-py.* Viable, and the best ecosystem for the later stats work; largest
    image and dependency surface to audit. **Rejected** for v1's security-first weighting.
  - *A multi-language stack.* Considered and dismissed: ingest, crypto, index, HTTP, and scheduling
    are one service. A second runtime means a second image, a second dependency surface, and a second
    thing to audit, buying nothing.
- **Consequences:** The crypto path is verified against **real Tryst backups** rather than shared
  with the app — so an interop test against a genuine `.tryst` file is a hard M1 exit criterion, not
  a nice-to-have. Buys a distroless, non-root, read-only-rootfs image nearly for free (constraint 6).

---

## D-7 — MIT, implemented from the format spec
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** Tryst is GPL-3.0. Sanctum starts private but should keep going-public open.
- **Decision:** MIT. The `TRYSTBK1` reader is implemented from Tryst's `docs/EXPORT_FORMAT.md` — the
  documented format — and **not** by copying `BackupCrypto.kt` or `BackupManager.kt`.
- **Alternatives considered:** *GPL-3.0*, copying Tryst's crypto verbatim for guaranteed
  compatibility. **Rejected** alongside D-6; it also forecloses licensing flexibility for no benefit
  once the format is specified.
- **Consequences:** No GPL derivation. Correctness now rests on the spec being accurate — if spec and
  code ever disagree, the code wins and the spec is a Tryst-side bug to file.

---

## D-8 — Multi-owner data model from day 1
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** v1 serves one person, but the stated endgame is two partners with separate spaces.
- **Decision:** Every blob, index row, and API path carries an **owner** from the first schema. v1
  provisions exactly one owner.
- **Alternatives considered:** *Single-owner v1, add ownership later.* Retrofitting an ownership
  column onto a shipped schema holding real data is precisely what principle 2 forbids, and lesson L6
  says migrations are the riskiest step. **Rejected.**
- **Consequences:** Slightly more schema than v1 strictly needs, and every query is owner-scoped from
  the start. Cheap now; unaffordable later.

---

## D-9 — Sharing = isolated vaults plus an opt-in aggregate
- **Date:** 2026-08-22
- **Status:** Accepted (design intent; implementation is v2+)
- **Context:** The owner's words: individual space for each person to store and see their own info,
  then the ability to share with a partner for an overall picture and combined stats.
- **Decision:** Per-owner vaults are isolated by default — neither owner can read the other's blobs
  or index. Sharing is an **explicit, revocable, per-owner opt-in** producing a derived aggregate
  view (overall picture, combined stats), not a merged dataset.
- **Alternatives considered:** *Full merged timeline.* Closest to the casual description, and it puts
  third parties named in either person's history — prior partners who never agreed to anything —
  onto a shared server. **Rejected**; the aggregate gets the value without the exposure.
- **Consequences:** The aggregate is computed, never stored decrypted; revoking a share must actually
  remove access, which constrains how aggregates may be cached. Needs its own ADR and a threat-model
  revision before any of it is built (see O-3).

---

## D-10 — Name: Sanctum
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** A container labelled `tryst-server` on the Unraid dashboard discloses the subject
  matter to anyone glancing at the GUI — which is the D-2 adversary exactly.
- **Decision:** **Sanctum** — a private, protected space. Neutral on a shared dashboard, and honest
  about the vault half.
- **Alternatives considered:** `liaison` (means "a link between two parties" — apt, but leans on the
  deferred half of the product); `rendezvous`; `boudoir` (most on-theme, least discreet — fails the
  dashboard test); `tryst-server` (clear, and discloses).
- **Consequences:** Discretion is a stated feature — keep it in mind for log lines, notification
  subjects, and share names, not just the container name.

---

## D-11 — Immutable, tamper-evident blob storage
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** The owner named *tampering* as a threat alongside disclosure.
- **Decision:** A stored blob is never rewritten in place. SHA-256 recorded at ingest and re-verified
  on read; `TRYSTBK1`'s AEAD independently authenticates the stream, so a flipped byte fails to
  decrypt. Verification at ingest includes a **real trial decrypt** — a backup that cannot be opened
  is not a backup. The manifest idiom mirrors the existing `immich-backup` script.
- **Alternatives considered:** *Hash only, no trial decrypt.* Proves the bytes are unchanged, not that
  they are openable — the exact failure that turns a backup into a false sense of security.
  **Rejected.**
- **Consequences:** Ingest costs a full decrypt pass (bounded by backup size, order 10^2 MB —
  acceptable). Corruption tests — flip a byte, expect failure — are a CI requirement, per principle
  12: a check that has never been forced to fire is not a check.

---

## D-12 — LAN-only in v1
- **Date:** 2026-08-22
- **Status:** Accepted
- **Context:** Partner access is deferred, so nothing needs to reach the box from outside.
- **Decision:** No port forwarding, no public DNS, no internet-facing reverse proxy. If remote access
  ever lands it is Tailscale/WireGuard — never an exposed port.
- **Alternatives considered:** *Public HTTPS behind a reverse proxy* — cert, auth, rate limiting,
  fail2ban, and a permanent ops burden, for a capability v1 does not have. **Rejected.**
- **Consequences:** The exposed-surface half of the Phase 3 audit is small in v1, and will need
  redoing in full the moment this changes. The web UI **still needs authentication** — LAN-only is
  not access control, and the D-2 adversary is already on the LAN.

---

## D-13 — Per-backup passwords: a per-owner set, sealed with the index
- **Date:** 2026-08-22
- **Status:** Accepted (resolves **O-1**)
- **Context:** Sanctum must trial-decrypt at ingest (D-11), and drop-folder ingest is asynchronous
  and best-effort by construction (D-1's consequence) — there is nobody at the keyboard when a file
  arrives from Syncthing. To open a `TRYSTBK1` the reader needs the **backup password** the user
  chose in Tryst at export time, which is independent of both the app PIN and Sanctum's own vault
  passphrase. Recorded evidence that users rotate this password: the owner's own backup set holds backups made
  with at least two different passwords — multi-password is not
  hypothetical.
- **Decision:** Sanctum stores a **set** of backup passwords per owner, sealed as part of the
  encrypted index (D-5). On ingest, each password in the set is tried in order until one
  authenticates the AEAD stream (or all fail, at which point the file is rejected with a log line
  and the owner is notified). The set is managed through the unlocked web UI — passwords are added,
  never edited in place. On successful ingest the winning password id is recorded on the backup row
  so restore, re-verify and any future decrypt skip straight to it.
- **Alternatives considered:**
  - *Prompt-per-ingest.* Nothing sensitive ever touches disk — the strongest posture on paper. But
    it **kills the watched drop folder** (F1), and it makes scheduled re-verification (F15) either
    impossible or dependent on the last-typed password living in memory anyway. **Rejected**: the
    property it protects (a password never at rest) is already violated by the vault-unlock
    passphrase's derived key sitting in RAM, and it removes a capability that motivated the
    project.
  - *One password per owner, no rotation support.* Simpler schema; forces the user to keep using
    the same Tryst backup password forever or lose access to old vault entries. **Rejected**:
    rotation happens in practice, and this hides the failure until the moment the user needs the
    backup.
  - *One shared password across all owners.* Undermines the D-8/D-9 isolation model
    (owner A trial-decrypts owner B's files by accident of shared credential). **Rejected.**
- **Consequences:** The vault passphrase (D-4) is genuinely the single root — it protects both the
  index and, transitively, every stored backup password. This is why residual risk R2 is stated
  the way it is. The "which password opened this" bookkeeping is the seam that makes cheap
  re-verification possible (F15). Adding a password on the UI is the natural place to fire a
  fresh-eyes "prune old passwords?" prompt, so the set does not grow forever.

---

## D-14 — Web UI auth: vault operator + per-owner accounts, split from day 1
- **Date:** 2026-08-22
- **Status:** Accepted (resolves **O-3**)
- **Context:** LAN-only is not access control (D-12's consequence) — the D-2 adversary is already
  on the LAN, so the UI needs authentication of its own. Two questions are entangled: (a) who is
  allowed to unlock the vault at all, and (b) who is allowed to see *this* owner's data once it is
  unlocked. Collapsing them works for v1 (one person = both) and breaks the moment there are two
  owners (D-8/D-9).
- **Decision:** Two credentials, distinct from day 1:
  1. **Vault-unlock passphrase** (D-4). Held by the operator — the person who administers the box.
     This is what boots the runtime key. In v1 that is you.
  2. **Owner login** — per-owner credential (username + passphrase) that gates access to an owner's
     backups, restore endpoint, and (v2) their share of the aggregate view. Stored in the index as
     an Argon2id (or PBKDF2, matching the app's KDF choice) hash + salt.
  In v1, both live with the same person; the unlock page presents both fields on one screen and
  the flow feels like one login. In v2, an owner who is not the operator simply cannot unlock the
  vault, which is correct — access to another owner's data is not something a partner should be
  able to grant themselves.
- **Alternatives considered:**
  - *Single credential doing double duty.* Simplest until it is not. Would require a full auth
    retrofit when the second owner is provisioned — and retrofitting auth onto a system that
    already holds real data is worse than retrofitting a schema (principle 2).
  - *SSO / OIDC / a real IdP.* Enormous ceremony for a two-person household service; a new
    dependency and a new network trust boundary; would need to work while the box is offline
    from the internet. **Rejected** as inconsistent with D-12.
- **Consequences:** Rate-limit the vault-unlock endpoint aggressively (small guessing budget per
  unit time, per source IP) — it protects everything else. Owner-login sessions must not survive a
  vault re-lock: the runtime key is gone, so serving anything past that is pretending. Session
  cookies live in tmpfs, `HttpOnly` + `Secure` + `SameSite=Strict`, and are rotated on unlock. A
  future ADR sets a session TTL; v1 default is short enough that walking away re-prompts.

---

## D-15 — Media in the index: counts only, from the ZIP central directory
- **Date:** 2026-08-22
- **Status:** Accepted (resolves **O-4**)
- **Context:** Every `TRYSTBK1` backup contains a `media/<id>` directory holding the decrypted photo
  bytes (re-encrypted by the container). At v1 scope Sanctum is a vault, not a viewer — but users
  reasonably ask "did this backup actually have my photos in it?" and the DATA_MODEL commitment is
  *counts, never content*.
- **Decision:** The M1 reader walks the ZIP **central directory only** and records:
  - the number of `media/*` entries;
  - the sum of their uncompressed sizes.
  Both go into `backup_table_count` under a reserved synthetic table name (`__media__`) so the
  existing schema handles it with no new column. The reader **does not extract** a single media
  byte in v1: no `Read()` is issued on any `media/*` entry, so the plaintext never leaves the AEAD
  stream.
- **Alternatives considered:**
  - *Full extraction with per-file SHA-256.* Would let Sanctum detect a partial-media backup that
    is technically valid but missing photos. Costs the most sensitive plaintext category the owner
    holds passing through the process, on every ingest — a large surface for a modest gain, and it
    fights hard constraint 2 constantly. **Rejected**: the AEAD already authenticates the whole
    stream, so a partial media set means the *export* was already partial.
  - *Skip media entirely.* Simplest; loses the "photos are there / photos are missing" signal that
    is the single most useful integrity check a user can eyeball. **Rejected**: the central
    directory read is nearly free and answers a real question.
- **Consequences:** Restoring is unaffected — restore is a byte-for-byte copy of the original blob,
  it does not walk the ZIP. If v2 ever needs media thumbnails for a shared view, that lands as a
  new capability, not a change to ingest. Explicit callout for M3: the ZIP walker must be
  index-only for `media/*`; adding a stray `Read()` there would silently violate constraint 2.

---

## D-16 — Vault-unlock KDF: Argon2id (distinct from owner login's PBKDF2)
- **Date:** 2026-08-22
- **Status:** Accepted (M2)
- **Context:** M2 needed a KDF to derive the runtime key from the operator's unlock passphrase.
  The sealed index (D-5) is the concrete artefact under attack: an adversary who obtains it can run
  arbitrary offline compute against every guess. That is exactly the threat model memory-hard KDFs
  were designed for. Owner login (D-14) already committed to PBKDF2-HMAC-SHA256, matching Tryst's
  own KDF — but that is a *different* threat (online guessing against a running service, protected
  by rate limits at N16), so the two decisions do not need to match.
- **Decision:** Vault unlock uses **Argon2id** (`golang.org/x/crypto/argon2.IDKey`) with
  production defaults `t=3, m=64 MiB, p=4` (OWASP 2023 guidance). Parameters are persisted in the
  vault manifest (`kdf`, `t`, `m_kib`, `p`, `salt`, `key_bits`) so a future ADR can raise them
  without breaking existing vaults, and so a test build can use `TestParams()` (`t=1, m=8 KiB, p=1`,
  fast) — with an `IsInsecureForTest()` guard so production callers cannot silently deploy them.
- **Alternatives considered:**
  - *PBKDF2-HMAC-SHA256* matching D-14. Symmetric with the owner-login KDF and one less crypto
    primitive to audit — but leaves the sealed blob's offline-attack surface without the
    memory-hard defence it deserves. **Rejected**: the two credentials protect against different
    adversaries, and the vault-unlock threat is the one where a memory-hard KDF actually matters.
  - *scrypt.* Older, well-analysed, similar properties. Argon2id is the current OWASP
    recommendation and has no serious drawback here. **Rejected** on preference, not principle.
- **Consequences:** Two KDFs in the codebase (Argon2id for vault-unlock; PBKDF2 for owner-login).
  Each is used exactly where its threat model wants it. Argon2id memory cost (~64 MiB per unlock)
  fits comfortably inside the container's 512 MiB limit (compose default). If M4's owner-login work
  finds a reason to consolidate on Argon2id for both, that is a new ADR — but do not do it just for
  aesthetic uniformity.

---

## D-17 — Session TTL: 30-minute idle, 12-hour absolute; RAM-only sessions
- **Date:** 2026-08-22
- **Status:** Accepted (M4; resolves **O-6**)
- **Context:** D-14 committed to per-owner login sessions, HttpOnly + SameSite=Strict, invalidated
  on re-lock (N17). O-6 deferred the TTL question. M4 wired the sessions and needs to answer.
- **Decision:**
  - **Storage:** sessions live in **process RAM** — not tmpfs, not the sealed index. RAM dies
    with the process, which is *stronger* than tmpfs (a tmpfs file can survive `docker restart -f`
    if inode caching pins it), and it means a container restart invalidates every session
    automatically without any GC. A re-lock also clears the map via `Manager.Clear()` (N17).
  - **Idle TTL:** 30 minutes, rolling. Every authenticated `Get` bumps `LastSeen`. A tab left
    open through a household member's browser session ages out on its own.
  - **Absolute TTL:** 12 hours, from `Issue` time. Bumping does NOT extend this. A cookie stolen
    from an active user still dies within the operator's workday.
  - **Session id:** 32 random bytes, base64url-encoded (2^256 space).
  - **Cookie flags:** `HttpOnly` always. `SameSite=Strict` always. `Secure` **only when the
    request came in over TLS** — Sanctum is LAN-only (D-12) with no cert, so an always-`Secure`
    cookie would be silently dropped by the browser. Documented as residual risk on the LAN;
    a future ADR can promote it when a reverse-proxy setup lands.
- **Alternatives considered:**
  - *Sessions on tmpfs, indexed by id.* Survives a container reload with `--restart on-failure`,
    which is convenience, not security. **Rejected** — the D-4 "vault re-locks on every restart"
    property extends naturally to sessions.
  - *No absolute max, only idle.* An always-active tab could hold a session indefinitely — bad
    if the cookie was ever exfiltrated. **Rejected.**
  - *Remote-IP-bound cookies.* Rejected because a phone that roams between Wi-Fi and cellular
    would be logged out at every hop, and Sanctum is expected to be usable from a phone
    browser.
- **Consequences:** Restarting Sanctum is a genuine full-reset of every session, matching how
  restart re-locks the vault — one mental model for both. The `Secure`-only-on-HTTPS carve-out is
  the one honest concession; noted in the residual-risk section of `THREAT_MODEL.md` (a future
  R-* row) and re-visited if Sanctum ever grows a proxy fronting it.

---

## D-18 — Unraid notification via a host-watched drop directory (resolves O-2)
- **Date:** 2026-08-23
- **Status:** Accepted (M5)
- **Context:** M5 introduces alerts — staleness (F9), verify failure, retention prune — that must
  reach the operator's Unraid dashboard. The canonical Unraid path is
  `/usr/local/emhttp/webGui/scripts/notify`, but that script lives on the host and cannot be
  invoked directly from inside a distroless container without either exposing the host filesystem
  or granting shell access — both hostile to hard constraint 6 (least-privilege container). The
  `immich-backup` script solved the same problem by living on the host as a User Script; Sanctum
  cannot, because Sanctum is a long-running service, not a cron job.
- **Decision:** Sanctum writes notification intents as JSON files into
  `${SANCTUM_NOTIFY_DIR}` (default `/data/notify/pending`). A tiny host-side dispatcher
  (`deploy/unraid-scripts/sanctum-notify-dispatch.sh`) runs as a User Script on a short cron,
  reads any `*.json` file, calls the host `notify` helper with the mapped fields, and moves the
  file into a sibling `sent/` directory on success (or `failed/` on error, with the reason). The
  container never mounts a host binary; the host script never reads Sanctum internals.
  - **Intent file schema** (v1): `{ "schema": 1, "at": <unix>, "severity": "normal|warning|alert",
    "subject": "...", "body": "...", "kind": "staleness|verify_failed|pruned|locked_since",
    "owner_label": "..."? }`. The `body` is bounded to ~4 KiB and MUST NOT contain a partner name,
    a filename, or an event detail from the index (N15) — the "locked-since" alert obeys this
    trivially by construction.
  - **Locked-safe alerting:** the notify path does not require the runtime key. When the vault
    is LOCKED, staleness cannot be evaluated per-owner (the sealed index is unreadable), but a
    cleartext sibling of `manifest.json` — `state.json` — records `locked_since` (unix seconds).
    The scheduler wakes, sees the vault is locked, computes `now - locked_since`, and emits a
    single "locked since X" intent per configured `SANCTUM_LOCKED_ALERT_AFTER` interval, subject
    to a debounce that survives restarts (last-fired timestamp stored in `state.json`). This
    satisfies R5 and the ROADMAP's M5 exit clause.
- **Alternatives considered:**
  - *Bind-mount the host `notify` script read-only into the container.* Sanctum could exec it.
    Fragile — Unraid moves emhttp scripts between versions; the container gains a filesystem
    dependency it cannot version-pin; and running arbitrary host scripts from a distroless image
    means shelling out from Go with all the injection risk that carries. **Rejected.**
  - *SMTP or a generic webhook.* Bypasses the Unraid dashboard the operator actually watches.
    Also introduces a secret (SMTP password, webhook token) that violates hard constraint 3.
    **Rejected.**
  - *systemd notify / dbus.* Not available on Unraid, which does not use systemd for user
    services. **Rejected.**
- **Consequences:** The dispatcher script becomes part of the deployment surface (RUNBOOK
  documents installing it as a User Script; principle 12 requires it be *test-fired* on the box
  before M6 exits). The intent file schema is versioned so a future channel change (a real Go
  Unraid notification client, if one ever exists) can supersede it without breaking history.
  Sanctum-side, the `notify.Notifier` interface has a `FileDropNotifier` implementation and a
  `NullNotifier` for tests; nothing in Sanctum-side code knows about Unraid.

---

## D-19 — Distribution: a scanned GHCR image per release tag; updates the normal Docker way
- **Status:** accepted 2026-11-05 (reverses the earlier "build from source, not published" stance)
- **Context:** Sanctum is meant to be usable by other Tryst users, who will not have a deploy key
  or want a Go build on their server. The container is least-privilege (hard constraint 6) and
  holds the most sensitive data its owner has, so it must not fetch-and-run code or get the docker
  socket (root-equivalent on the host).
- **Decision:** Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`: tests and guards, a
  local build, a non-root check, a Trivy vuln+secret scan, and only then a push to
  `ghcr.io/herbiewalker/sanctum:<version>` and a moving `:stable` (no `:latest`; amd64, with provenance and SBOM), plus a
  GitHub release. Users update the standard way: `docker compose pull && up -d`, or the Docker tab (install from `deploy/unraid-template.xml`: check, update, force update). Unraid's own
  update check. The container may also do a read-only check of the GitHub releases API and show
  "update available" (opt-in, `SANCTUM_UPDATE_CHECK`); it sends nothing but a User-Agent and
  never applies anything itself. The host-side `sanctum-update.sh` was removed before v0.1.0: it duplicated
  the in-app check and was the highest-privilege code in the repo. Source-build installs update by hand
  (`git checkout <tag>`, `docker compose up -d --build`). Nothing updates Sanctum automatically, so there
  is no release-signing key to hold, rotate or lose; supply-chain assurance is the image's build
  attestation and digest pinning.
- **Consequences:** Releases must be tagged, and the tag is the last step. Every restart re-locks
  the vault (D-4), so any update leaves Sanctum locked until a human unlocks it. The repo must go
  through the going-public checklist before other users can pull the package.
- **Alternatives rejected:** container self-update via docker socket; tracking `main`; Watchtower
  auto-pull (restart would silently re-lock the vault).

---

## D-20 — Notifications are sent by Sanctum itself to one pasted URL (revises D-18)
- **Status:** accepted 2026-11-05. D-18 stays valid as an optional channel but is no longer the default.
- **Context:** D-18 had Sanctum write files for a host User Script to deliver to Unraid's dashboard. In
  practice that failed: the script had to be installed by hand on every host, depended on Unraid-only
  tooling (and on `python3`, which Unraid does not ship), and for months its alerts sat unsent. It also
  cannot serve other Tryst users who do not run Unraid. D-18 rejected webhooks because they introduce a
  secret and cited hard constraint 3; that constraint is about vault key material (passphrase, derived
  key), and a notification URL is not that.
- **Decision:** `SANCTUM_NOTIFY_URL` takes one or more URLs: `ntfy://` (https) or `ntfy+http://` (LAN),
  a Discord or Slack webhook, or a generic webhook (POST JSON). Sanctum posts directly. The URL is
  treated as a credential: it lives only in the stack env, is never logged, and never appears in an
  error (logs show channel kind and host only); redirects are refused; timeouts are 10 s. When several
  channels are configured, delivery succeeds if any one works. `sanctum -notify-test` sends a test.
  Alert text carries only timestamps, day counts and version numbers, never backup contents, owner
  names or file names. The web UI also shows warnings: a banner on the unlock page when the vault has
  been locked for over an hour, and one on the status page when the newest backup is past the stale
  limit. The D-18 drop directory is now off unless `SANCTUM_NOTIFY_DIR` and a mount are added.
- **Consequences:** The vault container now makes outbound HTTPS calls (this, and the opt-in update
  check from D-19). Both need the network-surface lens in the next delta-audit. An operator who sets
  no URL gets a startup warning and UI banners only.
- **Alternatives rejected:** keeping the host script as the default; Apprise (a Python service);
  writing into Unraid's notification folder directly (private file format, no email or push).

---

## D-21 — Going public: history strategy (ACCEPTED 2026-11-11: option A)

- **Context:** the repo is private; the audit for going public (checklist 05, 2026-11-11) found no
  key or token in any commit, but found real host names, one credential written in prose, a personal data-folder path and a few personal
  details in HEAD and in 4 commit messages (see the pre-flip report). 40 commits, one branch, no tags,
  one author (`Sanctum`, GitHub noreply address), no issues or PRs, 33 Actions runs, one deploy key.
- **Options:** (A) **fresh orphan history**: one clean initial commit, published to a fresh repo.
  (B) **rewrite** with `git filter-repo` replacements, keeping the 40 commits. (C) **publish as-is**:
  rejected, the history carries the flagged strings.
- **Recommendation: A, published to a fresh repo.** Rename the current private repo to an archive
  name and create a new `sanctum` from the sanitized single commit. Reasons: zero residual risk in
  1.1 MB of history, no old objects reachable by SHA on GitHub (a force-push into the same repo leaves
  them fetchable until GitHub garbage-collects), Actions run titles and logs from the old repo do not
  carry over, and it matches the sibling repos (single clean commit). Cost: the 40-commit trail and
  every commit SHA quoted in `docs/AUDIT.md`, the brief and the CHANGELOG go away (the audit and
  CHANGELOG text survive; SHAs there get rewritten to descriptions), and the Unraid host clone must
  re-clone. B keeps the trail but needs a string-by-string rewrite whose completeness can only be
  checked by re-scanning, and still leaves the same-repo SHA-reachability problem.
- **Decision:** A. The public repo starts from one sanitized commit; the previous private history is
  kept in a private archive repo. Sanitizing removed host names, personal paths, a stray credential
  written in prose (rotated, see the pre-flip report) and stale commit SHAs from the docs.

---

## Open questions
> Decisions deferred on purpose. Each is a future ADR. Do not let these rot silently.

- **O-5 — Browser-side decryption** (D-3's deferred middle path). Revisit at the viewing milestone;
  would let a shared view work without the server ever holding a viewing key.
