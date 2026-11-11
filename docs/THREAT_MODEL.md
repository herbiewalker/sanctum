# Sanctum — Threat Model

> **Status:** v1 (2026-08-22) — aligned with the Phase 0 design (D-2, D-3, D-4, D-5, D-11, D-12).
> Covers the v1 vault scope only. **Partner sharing (D-9) requires a full revision of this document
> before any of it is built** — a second owner changes every row below.
>
> Keep current: a new feature that adds an asset or a surface is a change to this file (principle 3).

## Assets to protect

- **A1 — Encounter data.** Years of intimacy records: dates, partners, acts, locations, notes,
  ratings. The most sensitive category the owner holds. Disclosure is not recoverable.
- **A2 — Photo/media blobs** inside the backups. Same sensitivity, higher impact per item.
- **A3 — Partner identities.** Names of real people, including prior partners who have never
  consented to being on any server. Sanctum holds claims *about third parties*, not just about the
  owner. This is why D-9 rejects a merged timeline.
- **A4 — The backup passwords** Sanctum stores (D-3, D-13). Compromise means A1+A2 in full.
- **A5 — The runtime passphrase / derived key.** The root of everything above.
- **A6 — Metadata.** Backup timestamps, counts, cadence, per-owner activity. Reveals a great deal
  even without contents — which is why the index is encrypted too (D-5).
- **A7 — Availability of the backups themselves.** The point of the project. Losing them silently is
  as bad as never having them.
- **A8 — The existence of the service.** A container named for its purpose on a shared dashboard is
  itself a disclosure (D-10).

## Adversaries in scope

| ID | Adversary | Capability | Priority |
|----|-----------|------------|----------|
| T1 | **Curious household member** — family, children, guests | On the LAN; can browse to any host:port; can open SMB shares and the Unraid GUI; no root, not technically sophisticated, high opportunity | **High** |
| T2 | **Another device on the LAN** — a guest laptop, an IoT device, a compromised machine | Network reachability to the service; port scanning; no host access | **High** |
| T3 | **A tamperer** — anyone who can write to the inbox share or the appdata path | Can modify, truncate, replace, or plant files; may be T1 acting carelessly rather than maliciously | **High** |
| T4 | **Offline media** — a failed drive sent for RMA, a decommissioned disk, an appdata backup copied to another machine or to cloud storage | Full offline read of the array's bytes; unlimited time | **High** |
| T5 | **A compromised sibling container** on the same Docker host | Shares the Docker network; may read bind-mounted paths if granted | Medium |
| T6 | **A hostile backup file** — a crafted `TRYSTBK1` planted in the inbox | Arbitrary bytes into the parser: bad headers, absurd KDF counts, Zip-Slip names, zip bombs, truncated streams | Medium |
| T7 | **Opportunistic physical access** to a powered-off box | Takes disks; no running process to read | Medium |

## Out of scope (and why)

- **Root on the Unraid host while Sanctum is unlocked.** Root reads process memory and takes the
  runtime key; no design where the service can decrypt survives this. Explicitly accepted (D-2, R1).
- **A determined technical adversary with sustained physical possession of the running, unlocked box.**
  Same reason.
- **Compromise of the Android phone itself.** Tryst's own threat model owns that boundary.
- **Nation-state / targeted attacker.** Not the owner's threat model; the D-2 clarification was
  explicit that the adversary is the household and the LAN.
- **Traffic analysis on the LAN.** v1 is LAN-only with no external correlation to make.

## Threats → mitigations

| Threat | Mitigation |
|--------|-----------|
| T1/T2 browse to the service and read the vault | Boots **LOCKED** (D-4) — with no human at the keyboard there is nothing to see. Plus authentication on the UI: LAN-only is *not* access control (D-12's consequence) |
| T1 opens the SMB share or the Unraid file browser | Array holds only opaque `TRYSTBK1` blobs and a Tink-sealed index. Nothing is readable without the runtime key (D-5, hard constraint 2) |
| T1 sees "tryst-server" on the dashboard and gets curious | Neutral naming (D-10); neutral log lines and notification subjects |
| T3 modifies a stored blob | SHA-256 manifest re-verified on read **and** `TRYSTBK1`'s AEAD fails authentication on a flipped byte (D-11). Blobs are immutable — never rewritten in place |
| T3 deletes blobs | Detected by index-vs-store reconciliation; retention prune is the only sanctioned deleter. *(Residual: R3)* |
| T3 plants a file to poison the vault | Ingest is verify-first: a file that does not parse, hash, and **trial-decrypt** never enters the store (F2–F4, D-11) |
| T4 reads a pulled disk or a copied appdata backup | Ciphertext only. The key was never on the array (D-4) — this is the whole reason for manual unlock |
| T5 reads a bind-mounted path | Same ciphertext-only property; plus minimal mounts, no shared Docker network beyond what is needed |
| T5 escapes into the host | Non-root, read-only rootfs, `cap_drop: ALL`, no host network, resource limits (hard constraint 6, N3/N12/N14) |
| T6 sends an absurd PBKDF2 iteration count | Bounded 100k–5M on read, matching Tryst's own defence. Rejected, never attempted (N9) |
| T6 uses Zip-Slip entry names | Every entry name validated: no separators, no `..`, resolved path must stay inside the target dir (N10) |
| T6 sends a zip bomb or truncated stream | Size and entry-count caps on the trial decrypt; streaming, never load-whole-into-memory; failure is a rejection with a log line |
| T6 supplies a wrong password | AEAD fails on first read; ingest aborts cleanly with no partial write (N7) |
| A5 leaks through logs | N15 — logs never carry passphrases, keys, names, or content; verified by a log scrape during a real ingest |
| A7 silently lost — backups stop arriving | Staleness alerting (F9). The alert must fire even while LOCKED, reporting only "locked since X" |
| A7 silently lost — the index is corrupted | Rebuild-from-blobs (F12) is a required, tested recovery path (D-5's consequence) |
| A7 — a stored backup turns out not to open | Trial decrypt at ingest (D-11), plus scheduled re-verification (F15) |
| A3 exposed to a partner via sharing | Out of scope in v1 by construction — sharing is not built. D-9 pre-commits to an aggregate view rather than a merged timeline precisely to bound this |

## Residual risks

> The risks knowingly accepted. Naming them is the point.

- **R1 — Root on the host while unlocked reads everything.** Accepted (D-2). Unavoidable for any
  design where the service can decrypt. *Reduced by:* keeping the unlocked window short — lock the
  vault when not actively using it, rather than leaving it unlocked indefinitely.
- **R2 — Sanctum holds the backup passwords (A4).** The direct cost of D-3. A compromise of the
  unlocked process yields the passwords, and therefore every backup, including ones already
  restored elsewhere. *Not reduced by:* D-13 — a per-owner password set is still a set held in an unlocked process. *Would be reduced by:* O-5 (browser-side decryption), if it ever lands.
- **R3 — Deletion is not prevented, only detected.** Anyone who can write to the appdata path can
  delete blobs. Sanctum notices; it cannot stop it. *Reduced by:* Unraid share permissions, and by
  the fact that the phone remains the system of record.
- **R4 — The runtime passphrase is a single root.** One secret protects the index, the seals, and
  (D-13) the backup passwords. Forgetting it means the vault is unrecoverable — the same
  bargain Tryst's own backup password makes. *Mitigated by:* `CRITICAL_ASSETS.md` requiring a second
  copy that is not on this machine.
- **R5 — An unattended reboot leaves the vault locked and silently not ingesting.** The deliberate
  cost of D-4. *Mitigated by:* the locked-since alert path (D-18): the scheduler reads
  `vault/state.json` (cleartext, no secrets — just `locked_since` and `last_locked_alert_at`)
  and emits a warning through the drop-file notify channel while the vault is locked. The alert
  body says only "vault has been locked since X" — no owner names, no counts, no index reads
  possible. Debounced across restarts. RUNBOOK step for every reboot as belt-and-braces.
- **R7 — Notify channel silence.** The Unraid dispatcher script (D-18) is external to Sanctum
  and can be uninstalled or misconfigured; a silent notification path defeats R5. *Mitigated by:*
  principle 12 — the dispatcher must be test-fired on a real Unraid host before M6 exits (a
  notification path that has never fired is not a notification path). Files pile up in
  `pending/` when the dispatcher stops running, which is an operator-visible signal.
- **R6 — No independent verification that the trial decrypt matches what Tryst would produce.**
  D-6 chose a different crypto implementation from the app's. *Mitigated by:* the M1 exit criterion
  requiring interop against a genuine `.tryst` file — this risk stays open until that test passes.
