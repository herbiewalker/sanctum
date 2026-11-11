package index

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

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// migrator is one forward step. Migrations are additive-only (never
// destructive) per DATA_MODEL — a migrator that drops a column or repurposes
// one is a schema bug caught in code review, not something the harness
// prevents at runtime.
type migrator struct {
	toVersion int
	up        func(*sql.Tx) error
}

// migrations is the ordered list of forward steps. A fresh index runs every
// migrator in sequence; an existing index runs only the ones past its current
// schema version. Never rewrite a shipped migrator — add a new one.
var migrations = []migrator{
	{toVersion: 1, up: migrateToV1},
	{toVersion: 2, up: migrateToV2},
}

// migrateToV1 creates every schema-v1 table in a single transaction. If any
// step fails, none land — the DB stays at whatever version it was on.
func migrateToV1(tx *sql.Tx) error {
	if _, err := tx.Exec(schemaV1); err != nil {
		return fmt.Errorf("apply schemaV1 DDL: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO meta(key, value) VALUES ('index_schema_version', '1'),
                                                     ('created_at', strftime('%s','now'))`); err != nil {
		return fmt.Errorf("stamp meta: %w", err)
	}
	return nil
}

// migrateToV2 adds the optional, owner-written password hint. Additive only:
// existing rows get an empty hint.
func migrateToV2(tx *sql.Tx) error {
	if _, err := tx.Exec(`ALTER TABLE owner_backup_password ADD COLUMN hint TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add hint column: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta(key, value) VALUES ('index_schema_version', '2')`); err != nil {
		return fmt.Errorf("stamp meta: %w", err)
	}
	return nil
}

// currentSchemaVersion reads the meta row, or returns 0 for a fresh DB.
// A fresh DB is signalled by the meta table not existing yet — this is not
// an error, it means "run every migrator from the top".
func currentSchemaVersion(db *sql.DB) (int, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = 'index_schema_version'`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		// A missing meta table (fresh DB) surfaces as a "no such table" error
		// from the SQLite driver. Treat it as version 0 rather than plumbing
		// the driver-specific error type up.
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("index: index_schema_version %q not an integer: %w", v, err)
	}
	return n, nil
}

// migrate applies every pending migrator in order. Called from Open once the
// DB is unsealed and ready.
func migrate(db *sql.DB) error {
	from, err := currentSchemaVersion(db)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.toVersion <= from {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("index: begin migration to v%d: %w", m.toVersion, err)
		}
		if err := m.up(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("index: migrate to v%d: %w", m.toVersion, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("index: commit migration to v%d: %w", m.toVersion, err)
		}
	}
	return nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
