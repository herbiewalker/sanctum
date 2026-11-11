// ╭──────────────────────────────────────────────────────────────────╮
// │  ┌●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┐  │
// │  │                                                            │  │
// │  ●   ██╗  ██╗    ██╗    ██╗                                   ●  │
// │  │   ██║  ██║    ██║    ██║           herbiewalker            │  │
// │  │   ███████║    ██║ █╗ ██║──●──●──●──┐                       │  │
// │  │   ██╔══██║    ██║███╗██║           │                       │  │
// │  ●   ██║  ██║    ╚███╔███╔╝           ●───⏣  code · tools     ●  │
// │  │   ╚═╝  ╚═╝     ╚══╝╚══╝                    homelab         │  │
// │  │                                                            │  │
// │  └●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┘  │
// ╰──────────────────────────────────────────────────────────────────╯
// Package index owns Sanctum's SQLite index — the queryable metadata layer
// that sits in memory (on tmpfs while unlocked) and is sealed back to the
// array as a Tink-encrypted blob (D-5).
//
// The schema is defined by docs/DATA_MODEL.md; this file transcribes it. If
// the two ever disagree, DATA_MODEL wins and this file is what needs updating
// — never the other way around, because the doc is what a new session reads
// first.
package index

// CurrentSchemaVersion is the schema version Sanctum writes for a fresh index.
// A migration harness in migrations.go promotes older indexes forward.
const CurrentSchemaVersion = 1

// schemaV1 is the schema-v1 DDL, executed atomically in one transaction by
// migrateToV1. Every table shape below is what DATA_MODEL specifies; edits
// here must land in the same commit as an update to DATA_MODEL.md.
const schemaV1 = `
CREATE TABLE owner (
  id                TEXT PRIMARY KEY,
  label             TEXT NOT NULL,
  login_username    TEXT NOT NULL UNIQUE,
  login_kdf         TEXT NOT NULL,
  login_salt        BLOB NOT NULL,
  login_iterations  INTEGER NOT NULL,
  login_hash        BLOB NOT NULL,
  created_at        INTEGER NOT NULL,
  staleness_days    INTEGER
);

CREATE TABLE owner_backup_password (
  id            TEXT PRIMARY KEY,
  owner_id      TEXT NOT NULL REFERENCES owner(id) ON DELETE CASCADE,
  label         TEXT NOT NULL,
  passphrase    BLOB NOT NULL,
  added_at      INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX idx_obp_owner ON owner_backup_password(owner_id);

CREATE TABLE backup (
  id                       TEXT PRIMARY KEY,
  owner_id                 TEXT NOT NULL REFERENCES owner(id) ON DELETE CASCADE,
  sha256                   TEXT NOT NULL,
  size_bytes               INTEGER NOT NULL,
  ingested_at              INTEGER NOT NULL,
  source                   TEXT NOT NULL,
  original_filename        TEXT,
  container_version        INTEGER NOT NULL,
  kdf_iterations           INTEGER NOT NULL,
  tryst_schema_version     INTEGER,
  verified_at              INTEGER,
  verify_status            TEXT NOT NULL,
  opened_by_password_id    TEXT REFERENCES owner_backup_password(id) ON DELETE SET NULL,
  blob_path                TEXT NOT NULL,
  UNIQUE(owner_id, sha256)
);
CREATE INDEX idx_backup_owner_ingested ON backup(owner_id, ingested_at DESC);

CREATE TABLE backup_table_count (
  backup_id     TEXT NOT NULL REFERENCES backup(id) ON DELETE CASCADE,
  table_name    TEXT NOT NULL,
  row_count     INTEGER NOT NULL,
  total_bytes   INTEGER,
  PRIMARY KEY(backup_id, table_name)
);

CREATE TABLE event (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  at            INTEGER NOT NULL,
  owner_id      TEXT REFERENCES owner(id) ON DELETE SET NULL,
  kind          TEXT NOT NULL,
  detail        TEXT
);
CREATE INDEX idx_event_at ON event(at DESC);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
