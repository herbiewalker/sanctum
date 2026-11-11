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

	_ "modernc.org/sqlite" // pure-Go driver — cgo-free per ADR D-5/D-6
)

// sqliteDriver is the name registered by modernc.org/sqlite. Kept as a
// constant so a driver switch is one-line if that ever became necessary.
const sqliteDriver = "sqlite"

// Index is the SQLite handle plus its schema version. It is created either
// by OpenInMemory (M2 default — the live index lives on tmpfs, sealed to
// disk separately) or by openFile (for tests that need to inspect on-disk
// behaviour).
type Index struct {
	db      *sql.DB
	version int
}

// OpenInMemory creates a fresh in-memory SQLite database, applies every
// pending migration, and returns the ready index.
//
// The M2 lifecycle is:
//
//	OpenInMemory() → LoadSealed(runtimeKey) OR fresh writes
//	    ↓
//	work happens
//	    ↓
//	Seal(runtimeKey) → close
//
// The database bytes never touch the array as plaintext — Seal handles the
// hand-off through Tink (see seal.go).
func OpenInMemory() (*Index, error) {
	// modernc's DSN for a pure-in-memory DB: `:memory:` gives you a
	// per-connection DB by default, which breaks database/sql's connection
	// pool (each new connection sees its own DB). Use a named memory DB with
	// shared cache so every connection in the pool sees the same schema.
	dsn := "file::memory:?cache=shared"
	return open(dsn)
}

// OpenFile is used by tests that want to observe how the index would look
// on disk. Production always uses OpenInMemory + Seal.
func OpenFile(path string) (*Index, error) {
	return open("file:" + path)
}

func open(dsn string) (*Index, error) {
	db, err := sql.Open(sqliteDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("index: open: %w", err)
	}
	// modernc.org/sqlite defaults are fine; enforce foreign keys explicitly
	// so ON DELETE CASCADE/SET NULL behave as the schema advertises.
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("index: enable FKs: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	v, err := currentSchemaVersion(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Index{db: db, version: v}, nil
}

// Close releases the underlying handle. Call after a successful Seal, or on
// a shutdown path that has already accepted the loss.
func (i *Index) Close() error {
	if i == nil || i.db == nil {
		return nil
	}
	return i.db.Close()
}

// SchemaVersion returns the schema version this index is at. Should equal
// CurrentSchemaVersion after Open.
func (i *Index) SchemaVersion() int { return i.version }

// DB exposes the underlying handle for internal packages that need to run
// queries this package does not yet wrap. Keep this to the minimum needed;
// every query worth caring about should get a typed method here.
func (i *Index) DB() *sql.DB { return i.db }

// --- typed operations (v1 essentials) ---------------------------------------

// Owner represents an owner row without login credential BLOBs — the caller
// asks for those via GetOwnerAuth when they need to verify a login.
type Owner struct {
	ID            string
	Label         string
	LoginUsername string
	CreatedAt     int64
	StalenessDays *int
}

// OwnerAuth is the credential-side of an owner row. Never logged, never
// returned across a wire boundary.
type OwnerAuth struct {
	KDF        string
	Salt       []byte
	Iterations int
	Hash       []byte
}

// CreateOwner inserts an owner row. Fails if the login_username collides.
func (i *Index) CreateOwner(o Owner, auth OwnerAuth) error {
	_, err := i.db.Exec(
		`INSERT INTO owner
		 (id, label, login_username, login_kdf, login_salt, login_iterations, login_hash, created_at, staleness_days)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		o.ID, o.Label, o.LoginUsername,
		auth.KDF, auth.Salt, auth.Iterations, auth.Hash,
		o.CreatedAt, nullableInt(o.StalenessDays),
	)
	return wrapExec("CreateOwner", err)
}

// GetOwner returns the profile fields for an owner id.
func (i *Index) GetOwner(id string) (Owner, error) {
	var o Owner
	var staleness sql.NullInt64
	err := i.db.QueryRow(
		`SELECT id, label, login_username, created_at, staleness_days FROM owner WHERE id = ?`,
		id,
	).Scan(&o.ID, &o.Label, &o.LoginUsername, &o.CreatedAt, &staleness)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Owner{}, ErrNotFound
		}
		return Owner{}, err
	}
	if staleness.Valid {
		v := int(staleness.Int64)
		o.StalenessDays = &v
	}
	return o, nil
}

// BackupPassword is one entry in an owner's D-13 password set.
type BackupPassword struct {
	ID         string
	OwnerID    string
	Label      string
	Hint       string // optional, owner-written; never shown outside the signed-in UI
	Passphrase []byte
	AddedAt    int64
	LastUsedAt *int64
}

// AddBackupPassword appends a new entry. D-13: password entries are
// add-only; use DeleteBackupPassword to remove one.
func (i *Index) AddBackupPassword(p BackupPassword) error {
	_, err := i.db.Exec(
		`INSERT INTO owner_backup_password(id, owner_id, label, hint, passphrase, added_at, last_used_at)
		 VALUES (?,?,?,?,?,?,?)`,
		p.ID, p.OwnerID, p.Label, p.Hint, p.Passphrase, p.AddedAt, nullableInt64(p.LastUsedAt),
	)
	return wrapExec("AddBackupPassword", err)
}

// ListBackupPasswords returns an owner's set ordered so the most recently
// successful entry comes first. Ingest walks this ordering (F18).
func (i *Index) ListBackupPasswords(ownerID string) ([]BackupPassword, error) {
	rows, err := i.db.Query(
		`SELECT id, owner_id, label, hint, passphrase, added_at, last_used_at
		 FROM owner_backup_password
		 WHERE owner_id = ?
		 ORDER BY COALESCE(last_used_at, 0) DESC, added_at DESC`,
		ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupPassword
	for rows.Next() {
		var p BackupPassword
		var lastUsed sql.NullInt64
		if err := rows.Scan(&p.ID, &p.OwnerID, &p.Label, &p.Hint, &p.Passphrase, &p.AddedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			v := lastUsed.Int64
			p.LastUsedAt = &v
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteBackupPassword removes one entry. Any backup row that referenced it
// has its opened_by_password_id set to NULL by the FK (schema.go).
func (i *Index) DeleteBackupPassword(id string) error {
	_, err := i.db.Exec(`DELETE FROM owner_backup_password WHERE id = ?`, id)
	return err
}

// Backup is one indexed TRYSTBK1 file. Sanctum stores COUNTS about it and
// nothing from its contents (DATA_MODEL).
type Backup struct {
	ID                 string
	OwnerID            string
	SHA256             string
	SizeBytes          int64
	IngestedAt         int64
	Source             string
	OriginalFilename   string
	ContainerVersion   int
	KDFIterations      int
	TrystSchemaVersion *int
	VerifiedAt         *int64
	VerifyStatus       string
	OpenedByPasswordID *string
	BlobPath           string
}

// InsertBackup adds a backup row and every table_count in one transaction.
// Duplicate SHA per owner returns ErrDuplicate — the ingest path uses this
// to satisfy F13 without a separate query.
func (i *Index) InsertBackup(b Backup, tableCounts map[string]TableCount) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	_, err = tx.Exec(
		`INSERT INTO backup
		 (id, owner_id, sha256, size_bytes, ingested_at, source, original_filename,
		  container_version, kdf_iterations, tryst_schema_version, verified_at,
		  verify_status, opened_by_password_id, blob_path)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		b.ID, b.OwnerID, b.SHA256, b.SizeBytes, b.IngestedAt, b.Source, b.OriginalFilename,
		b.ContainerVersion, b.KDFIterations, nullableInt(b.TrystSchemaVersion),
		nullableInt64(b.VerifiedAt), b.VerifyStatus, nullableString(b.OpenedByPasswordID), b.BlobPath,
	)
	if err != nil {
		return classifyBackupInsertErr(err)
	}
	for name, tc := range tableCounts {
		if _, err := tx.Exec(
			`INSERT INTO backup_table_count(backup_id, table_name, row_count, total_bytes)
			 VALUES (?,?,?,?)`,
			b.ID, name, tc.RowCount, nullableInt64(tc.TotalBytes),
		); err != nil {
			return fmt.Errorf("insert table_count %q: %w", name, err)
		}
	}
	return tx.Commit()
}

// TableCount is one row in backup_table_count. TotalBytes is used by the
// __media__ synthetic row (D-15) and is nullable everywhere else.
type TableCount struct {
	RowCount   int
	TotalBytes *int64
}

// ListBackups returns backups for one owner, newest first.
func (i *Index) ListBackups(ownerID string) ([]Backup, error) {
	rows, err := i.db.Query(
		`SELECT id, owner_id, sha256, size_bytes, ingested_at, source, original_filename,
		        container_version, kdf_iterations, tryst_schema_version, verified_at,
		        verify_status, opened_by_password_id, blob_path
		 FROM backup WHERE owner_id = ? ORDER BY ingested_at DESC`,
		ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		var b Backup
		var schemaV sql.NullInt64
		var verifiedAt sql.NullInt64
		var opened sql.NullString
		if err := rows.Scan(
			&b.ID, &b.OwnerID, &b.SHA256, &b.SizeBytes, &b.IngestedAt, &b.Source, &b.OriginalFilename,
			&b.ContainerVersion, &b.KDFIterations, &schemaV, &verifiedAt,
			&b.VerifyStatus, &opened, &b.BlobPath,
		); err != nil {
			return nil, err
		}
		if schemaV.Valid {
			v := int(schemaV.Int64)
			b.TrystSchemaVersion = &v
		}
		if verifiedAt.Valid {
			v := verifiedAt.Int64
			b.VerifiedAt = &v
		}
		if opened.Valid {
			s := opened.String
			b.OpenedByPasswordID = &s
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetTableCounts returns the table_count rows for one backup.
func (i *Index) GetTableCounts(backupID string) (map[string]TableCount, error) {
	rows, err := i.db.Query(
		`SELECT table_name, row_count, total_bytes FROM backup_table_count WHERE backup_id = ?`,
		backupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]TableCount{}
	for rows.Next() {
		var name string
		var count int
		var totalBytes sql.NullInt64
		if err := rows.Scan(&name, &count, &totalBytes); err != nil {
			return nil, err
		}
		tc := TableCount{RowCount: count}
		if totalBytes.Valid {
			v := totalBytes.Int64
			tc.TotalBytes = &v
		}
		out[name] = tc
	}
	return out, rows.Err()
}

// LogEvent appends a neutral audit-trail row. `detail` must be non-sensitive
// (DATA_MODEL / N15) — hash prefixes and reason codes only.
func (i *Index) LogEvent(at int64, ownerID, kind, detail string) error {
	_, err := i.db.Exec(
		`INSERT INTO event(at, owner_id, kind, detail) VALUES (?,?,?,?)`,
		at, nullableString(&ownerID), kind, detail,
	)
	return err
}

// --- errors + helpers -------------------------------------------------------

var (
	ErrNotFound  = errors.New("index: not found")
	ErrDuplicate = errors.New("index: duplicate backup (same SHA-256 for this owner)")
)

func wrapExec(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("index %s: %w", op, err)
}

func classifyBackupInsertErr(err error) error {
	if err == nil {
		return nil
	}
	// The modernc driver returns errors whose message contains "UNIQUE
	// constraint failed" — matching on the string is fragile but the driver
	// does not export typed errors for constraint failures.
	if s := err.Error(); s != "" &&
		(contains(s, "UNIQUE constraint failed: backup.owner_id, backup.sha256") ||
			contains(s, "UNIQUE constraint failed: backup.sha256")) {
		return fmt.Errorf("%w: %v", ErrDuplicate, err)
	}
	return err
}

func contains(s, sub string) bool {
	// Manual to avoid a strings import purely for this helper.
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func nullableInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}
func nullableInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
func nullableString(p *string) any {
	if p == nil || *p == "" {
		return nil
	}
	return *p
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
