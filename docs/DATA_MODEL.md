# Sanctum — Data Model

> **Status:** Design intent — **index schema v2 (v1 + optional password hint).** Lands in M1/M2. The migration
> rule below is in force from the first stateful commit (principle 2 / lesson L6), not added later.

Two independent things are versioned here, and conflating them is the classic mistake:

| Thing | Versioned as | Owned by |
|-------|--------------|----------|
| Sanctum's **index schema** | `index_schema_version` | this document |
| Sanctum's **on-disk vault layout** | `layout_version` in `vault/manifest.json` | this document |
| Tryst's **backup container** (`TRYSTBK1` v1) | its own header byte | Tryst's `docs/EXPORT_FORMAT.md` — **read-only to us** |
| Tryst's **database schema** (v15 today) | `schemaVersion` inside `data.json` | Tryst |

Sanctum **records** the last two and never dictates them. A backup from a future Tryst schema must
still be storable and restorable even if Sanctum cannot fully interpret its contents — a vault that
refuses to hold a backup because it is too new has failed at its one job.

## Entities (index, schema v1)

### `owner`
| Field | Type | Notes |
|-------|------|-------|
| `id` | TEXT | PK, ULID |
| `label` | TEXT | display name, owner-chosen. Keep it neutral (D-10) |
| `login_username` | TEXT | UNIQUE. The identifier for the owner login (D-14) |
| `login_kdf` | TEXT | KDF identifier — `pbkdf2-sha256` in v1, matching the app's KDF choice |
| `login_salt` | BLOB | random per owner |
| `login_iterations` | INTEGER | KDF cost |
| `login_hash` | BLOB | KDF output — never a reversible ciphertext, never the passphrase |
| `created_at` | INTEGER | unix seconds, UTC |
| `staleness_days` | INTEGER | per-owner threshold for F9; NULL = use the global default |

> v1 provisions exactly one row. The table exists from day 1 anyway (D-8) — retrofitting ownership
> onto a shipped schema holding real data is what principle 2 forbids. The `login_*` columns split
> "unlock the vault" from "prove who you are" (D-14) so the second owner does not require an auth
> retrofit; in v1 both credentials live with the same person and the unlock page collapses to one
> screen.

### `owner_backup_password`
| Field | Type | Notes |
|-------|------|-------|
| `id` | TEXT | PK, ULID |
| `owner_id` | TEXT | FK → `owner.id`, cascade delete |
| `label` | TEXT | owner-chosen — e.g. `"pre-2026-08"`. Never the passphrase |
| `hint` | TEXT | optional owner-written memory aid (schema v2, `DEFAULT ''`, max 200 chars). Lives only in the sealed index; shown only to the signed-in owner; never in notifications, logs or the manifest |
| `passphrase` | BLOB | the Tryst backup password. **Only ever seen in cleartext inside the encrypted index**, which lives on tmpfs while unlocked and is sealed to the array as a Tink blob (D-5) |
| `added_at` | INTEGER | unix seconds, UTC |
| `last_used_at` | INTEGER | nullable — updated when this password authenticates a backup |

> The per-owner set from D-13. Trial decrypt at ingest walks the set in `last_used_at DESC, added_at
> DESC` order and rejects the file when none authenticate. When a password wins, its `id` is
> written to `backup.opened_by_password_id` so restore and re-verify skip straight to it — the same
> password does not need to be re-discovered every time. Password entries are **added, never edited
> in place**; a superseded entry is deleted through the UI, not silently rotated.

### `backup`
| Field | Type | Notes |
|-------|------|-------|
| `id` | TEXT | PK, ULID |
| `owner_id` | TEXT | FK → `owner.id`. **Every query is owner-scoped** |
| `sha256` | TEXT | of the whole original file. UNIQUE per owner — this is how F13 refuses duplicates |
| `size_bytes` | INTEGER | |
| `ingested_at` | INTEGER | unix seconds, UTC. **Sanctum's clock**, never a timestamp from inside the backup |
| `source` | TEXT | `inbox` \| `upload` |
| `original_filename` | TEXT | as delivered; informational only, never used to build a path |
| `container_version` | INTEGER | the `TRYSTBK1` header's format version byte |
| `kdf_iterations` | INTEGER | from the header, after bounds validation |
| `tryst_schema_version` | INTEGER | from `data.json`; nullable if the backup could not be interpreted |
| `verified_at` | INTEGER | last successful full verify (hash + trial decrypt) |
| `verify_status` | TEXT | `ok` \| `hash_mismatch` \| `decrypt_failed` \| `unverified` |
| `opened_by_password_id` | TEXT | FK → `owner_backup_password.id`; nullable while `verify_status = unverified`. Set the moment ingest finds a working password (D-13) |
| `blob_path` | TEXT | relative to the vault root; derived from `id`, **never** from `original_filename` |

### `backup_table_count`
| Field | Type | Notes |
|-------|------|-------|
| `backup_id` | TEXT | FK → `backup.id`, cascade delete |
| `table_name` | TEXT | e.g. `encounters`, `partners`; plus reserved synthetic rows below |
| `row_count` | INTEGER | rows in the table, OR the count for a synthetic row |
| `total_bytes` | INTEGER | nullable — used by the `__media__` synthetic row for the summed uncompressed size |

> PK `(backup_id, table_name)`. This is deliberately the **only** thing extracted from `data.json`:
> counts, never content. It is enough to answer "did this backup actually get bigger?" — the single
> most useful integrity signal — without any encounter data entering the index.
>
> **Reserved synthetic rows** (D-15) — computed from the ZIP central directory, never from a
> decrypted entry read:
>
> | `table_name` | Meaning |
> |--------------|---------|
> | `__media__`  | `row_count` = number of `media/*` entries; `total_bytes` = sum of their uncompressed sizes. **The reader must not `Read()` a `media/*` entry in v1**; central-directory read only, so no plaintext leaves the AEAD stream. |

### `event`
| Field | Type | Notes |
|-------|------|-------|
| `id` | INTEGER | PK autoincrement |
| `at` | INTEGER | unix seconds, UTC |
| `owner_id` | TEXT | nullable (service-level events) |
| `kind` | TEXT | `ingest_ok` \| `ingest_rejected` \| `verify_failed` \| `pruned` \| `unlocked` \| `locked` \| `alert_sent` |
| `detail` | TEXT | **neutral, non-sensitive** — a hash prefix and a reason code, never a filename that leaks content, never a partner name (N15) |

> The audit trail for T3 (tampering). It is also the thing most likely to leak by accident, hence
> the constraint on `detail`.

### `meta`
| Field | Type | Notes |
|-------|------|-------|
| `key` | TEXT | PK — `index_schema_version`, `created_at`, `last_seal_at` |
| `value` | TEXT | |

## Relationships

- `owner` 1 → N `backup` (cascade delete: pruning an owner removes their index rows; **blobs are
  deleted only by an explicit, logged prune**, never as a silent side effect).
- `owner` 1 → N `owner_backup_password` (cascade — a removed owner takes their password set with
  them, at which point any remaining blobs of theirs are unopenable and should already be gone).
- `backup` N → 1 `owner_backup_password` (`opened_by_password_id`; nullable). `ON DELETE SET NULL`,
  because deleting a password should never delete a backup — it just marks it as needing rediscovery
  on the next re-verify.
- `backup` 1 → N `backup_table_count` (cascade).
- `owner` 1 → N `event` (nullable side).

## On-disk layout (`layout_version` 1)

```
/mnt/user/appdata/sanctum/
  vault/
    manifest.json            # layout_version + owner dir map. CLEARTEXT — deliberately: it is the
                             # only thing that must be readable to rebuild from zero. Contains no
                             # secrets, no names, no counts. Owner ids only.
    state.json               # cleartext operational state read WHILE LOCKED (D-18): locked_since
                             # unix-seconds, last_locked_alert_at unix-seconds. No secrets, no
                             # index content — just wall-clock timestamps the operator already sees
                             # in logs. Used by the scheduler to emit "locked since X" alerts.
    <owner-id>/
      <backup-id>.tryst      # the ORIGINAL bytes, unmodified. Immutable. (D-11)
      <backup-id>.sha256     # the manifest entry, written once at ingest
  index.sealed               # SQLite index, Tink-encrypted under the runtime key (D-5)
  index.sealed.prev          # previous seal, kept for one generation — a failed seal must not
                             # destroy the last good index
  notify/                    # OPTIONAL — created only when SANCTUM_NOTIFY_DIR is set (D-18).
    pending/                 # Sanctum writes intent .json files here (schema in D-18).
    sent/                    # dispatcher moves delivered files here.
    failed/                  # dispatcher moves files here on error, with reason suffix.
```

Nothing else. No logs on the array, no temp files, no cache. The tmpfs mount holds the live SQLite
file and any transient decrypt buffer, and both die with the container.

**Why `.tryst` files sit on disk with their own extension:** the blob *is* the deliverable. Restore
(F10/N8) is a byte-for-byte copy out, so the safest storage format is "exactly what Tryst wrote,
untouched". Re-wrapping it in a Sanctum container would add a second crypto layer to get wrong for
no benefit, and would break the property that a restored file is provably identical.

## Schema / migration rules (READ BEFORE CHANGING THE SCHEMA)

The index is a **derived cache** — rebuildable from the blobs (F12) — which makes migration far less
dangerous here than in Tryst. That is a reason to be relaxed about index migrations, and **not** a
reason to be relaxed about the vault layout, which holds the only copies.

**Index schema changes:**
1. Bump `index_schema_version` in `meta`.
2. Add a **forward migration** — additive, nullable. Never drop or repurpose a column.
3. Add a migration test that migrates a v(N-1) index and asserts the resulting schema.
4. Confirm rebuild-from-blobs (F12) produces the same schema — the two paths must not drift.
5. If a migration is ever genuinely impossible, the fallback is "discard the index and rebuild".
   That must remain a real, tested option, never a theoretical one.

**Vault layout changes** are a different and much higher bar:
1. Bump `layout_version` in `manifest.json`.
2. The migration must be **non-destructive and resumable** — it moves or adds, it never deletes
   until the new layout is verified complete.
3. Every blob's SHA-256 is re-verified after the move, before anything old is removed.
4. There is no "just rebuild" escape hatch here. These are the only copies Sanctum holds.

**Tryst schema changes** (e.g. v15 → v16) require nothing from Sanctum by design: `data.json` is
read generically for counts only. A new table appears as a new `backup_table_count` row. If a future
Tryst release changes the *container* format to `TRYSTBK2`, that is a real Sanctum change — the
reader must keep handling v1 blobs already in the vault forever.
