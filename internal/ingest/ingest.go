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
// Package ingest is Sanctum's one pipeline for turning a TRYSTBK1 file into
// an indexed blob.
//
// Every path that gains a backup — the inbox watcher (F1), the browser upload
// (F2), an operator-initiated re-index — funnels through this package. The
// pipeline is documented in docs/ARCHITECTURE.md under "Ingest (the path
// that matters most)". Ordering is deliberate:
//
//  1. Reject fast if LOCKED — before touching input (D-4).
//  2. Stream input → tmpfs .tmp file, hashing as we go, bounded by
//     trystbk.MaxBackupBytes.
//  3. ParseHeader from tmpfs — cheap validate before any KDF work.
//  4. Duplicate check by SHA against index for this owner (F13).
//  5. Walk the owner's password set (D-13/F18) in last_used_at DESC order.
//  6. First success → Manifest + winning password id. None matched → reject.
//  7. blobstore.Put — atomic (tmp+rename inside vault); verify Put's SHA
//     matches ours.
//  8. InsertBackup + backup_table_count rows + update
//     owner_backup_password.last_used_at + LogEvent, in one transaction.
//
// The tmpfs staging file is unlinked before return on every path. Plaintext
// exists only in that tmpfs file (bounded lifetime) and in the AEAD stream
// consumed inside trystbk.Open (never persisted). guard-no-plaintext asserts
// nothing readable as ZIP or JSON ever appears in the vault directory.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/trystbk"
)

// Source identifies where a file arrived from. Recorded on the backup row
// (DATA_MODEL: `backup.source`) so operators can distinguish an operator
// upload from an unattended drop-folder ingest at a glance.
type Source string

const (
	SourceInbox  Source = "inbox"
	SourceUpload Source = "upload"
)

// Result summarises a successful ingest. Returned to the caller and logged
// in a neutral form; never carries encounter content or passwords.
type Result struct {
	BackupID           string
	SHA256             string // hex
	SizeBytes          int64
	TrystSchemaVersion int
	TableCounts        map[string]int
	OpenedByPasswordID string
}

// IDGenerator produces a new ULID-shaped id for a backup row. Kept as an
// injected function so tests can force deterministic ids without dragging
// in a ULID dependency here. Production wiring in cmd/sanctum will pass a
// real generator.
type IDGenerator func() string

// Clock is time.Now, injectable for tests.
type Clock func() time.Time

// Service is the ingest surface. One instance per vault, held by the HTTP
// handler and the watcher.
//
// The Service does NOT hold the runtime key itself — that lives in
// vaultkey.Key inside the caller. The Service holds the unsealed index and
// the blob store, which is exactly what an unlocked vault looks like. When
// the vault re-locks, the caller invokes Lock() to prevent further ingests
// even if a stale reference is used.
type Service struct {
	store    *blobstore.Store
	idx      *index.Index
	tmpDir   string
	newID    IDGenerator
	now      Clock
	logger   *slog.Logger
	onCommit func()

	// stageSem allows ONE ingest in flight (D09). Each ingest stages up to
	// MaxBackupBytes on the same tmpfs that holds the live index; two at once
	// can fill it and starve the index and its seal.
	stageSem chan struct{}

	// locked is checked at the top of every Ingest call. atomic.Bool is
	// fast and enough — this is a best-effort defence, not a security
	// boundary. The real security boundary is the runtime key being zeroed
	// on Lock (D-4), which the caller does in the same code path.
	locked atomic.Bool
}

// Options configure the Service. TmpDir is REQUIRED — the ingest pipeline
// must never fall back to on-disk /tmp (hard constraint 2). The Vault layer
// enforces the tmpfs-backed check on this path before it constructs a
// Service, so ingest.New just requires the field to be set.
type Options struct {
	TmpDir string       // required — must be the same tmpfs Vault verified
	NewID  IDGenerator  // required in production; defaults to a monotonic-shaped hex id
	Now    Clock        // defaults to time.Now
	Logger *slog.Logger // defaults to slog.Default()

	// OnCommit, if set, is called after each backup is durably indexed (D01:
	// the vault uses it to checkpoint-seal the index promptly).
	OnCommit func()
}

// New wires a Service. Fails if store or idx is nil, or if TmpDir is unset —
// those are non-optional because the whole pipeline is a function of them
// and, in TmpDir's case, silently falling back to os.TempDir() would put
// decrypted staging on the array.
func New(store *blobstore.Store, idx *index.Index, opt Options) (*Service, error) {
	if store == nil {
		return nil, errors.New("ingest: nil blobstore")
	}
	if idx == nil {
		return nil, errors.New("ingest: nil index")
	}
	if opt.TmpDir == "" {
		return nil, errors.New("ingest: TmpDir is required (must be tmpfs — see hard constraint 2)")
	}
	s := &Service{
		store:    store,
		idx:      idx,
		tmpDir:   opt.TmpDir,
		newID:    opt.NewID,
		now:      opt.Now,
		logger:   opt.Logger,
		onCommit: opt.OnCommit,
		stageSem: make(chan struct{}, 1),
	}
	if s.newID == nil {
		s.newID = defaultIDGen()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

// Lock marks the service as locked; subsequent Ingest calls return
// ErrVaultLocked. Idempotent.
func (s *Service) Lock() { s.locked.Store(true) }

// Unlock clears the locked flag. The caller is responsible for ensuring the
// underlying index is still usable (i.e., the runtime key that unsealed it
// still exists in memory).
func (s *Service) Unlock() { s.locked.Store(false) }

// IsLocked reports the current state, primarily for tests and health probes.
func (s *Service) IsLocked() bool { return s.locked.Load() }

// IngestFile is a convenience over IngestReader that opens the given path.
// The source is set to SourceInbox; callers using this from a non-watcher
// code path should switch to IngestReader with an explicit source.
func (s *Service) IngestFile(ownerID, path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ingest: open %q: %w", path, err)
	}
	defer f.Close()
	return s.IngestReader(ownerID, SourceInbox, filepath.Base(path), f)
}

// IngestReader runs the full pipeline. The reader is consumed (and, in the
// tmpfs stage, drained to disk) before any decrypt attempt.
//
// The reader is NOT closed by IngestReader — the caller retains ownership
// of the underlying resource, since callers vary (http.Request.Body wants
// its own Close semantics, os.File wants a defer, etc.).
func (s *Service) IngestReader(ownerID string, source Source, filename string, r io.Reader) (*Result, error) {
	if s.locked.Load() {
		return nil, ErrVaultLocked
	}

	// D09: one ingest at a time. A browser upload is refused immediately when
	// another is running (the caller shows "busy"); the inbox watcher simply
	// waits its turn.
	if source == SourceUpload {
		select {
		case s.stageSem <- struct{}{}:
		default:
			return nil, ErrBusy
		}
	} else {
		s.stageSem <- struct{}{}
	}
	defer func() { <-s.stageSem }()
	if s.locked.Load() {
		return nil, ErrVaultLocked
	}

	// Owner has to exist. Cheap check — a bad ownerID here is a caller bug,
	// not a T6 rejection.
	if _, err := s.idx.GetOwner(ownerID); err != nil {
		if errors.Is(err, index.ErrNotFound) {
			return nil, ErrUnknownOwner
		}
		return nil, err
	}

	// --- stage 1: copy to tmpfs, hashing as we go --------------------------
	stagePath, stageSHA, stageSize, err := s.stageInput(r)
	if err != nil {
		return nil, err
	}
	// Every path out of here removes the tmpfs staging file. This is the
	// enforcement of hard constraint 2 for the ingest side: plaintext of an
	// inbound file has bounded lifetime inside this process.
	defer os.Remove(stagePath)

	sha256Hex := hex.EncodeToString(stageSHA)

	// --- stage 2: header parse (cheap) -------------------------------------
	if err := s.headerProbe(stagePath); err != nil {
		s.logRejected(ownerID, sha256Hex, "bad_header", err)
		return nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}

	// --- stage 3: F13 duplicate check --------------------------------------
	//
	// Cheap SELECT; if we find a match, save the caller the KDF work and
	// bail early. A race with a concurrent ingest of the same file is caught
	// later at the blobstore.Put step (ErrBlobExists → ErrDuplicate).
	if dupID, err := s.findDuplicate(ownerID, sha256Hex); err != nil {
		return nil, err
	} else if dupID != "" {
		s.logger.Info("ingest duplicate",
			"owner", ownerID, "sha", sha256Hex[:16], "existing_id", dupID)
		return nil, ErrDuplicate
	}

	// --- stage 4: walk the D-13 password set -------------------------------
	passwords, err := s.idx.ListBackupPasswords(ownerID)
	if err != nil {
		return nil, fmt.Errorf("ingest: list passwords: %w", err)
	}
	if len(passwords) == 0 {
		return nil, ErrNoOwnerPasswords
	}

	manifest, winnerID, err := s.trialDecrypt(stagePath, passwords)
	if err != nil {
		// A structural failure — bad ZIP, missing data.json, etc.
		s.logRejected(ownerID, sha256Hex, "structural", err)
		return nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if winnerID == "" {
		// No password matched. Log with hash prefix only; the passwords
		// themselves never touch a log line.
		s.logRejected(ownerID, sha256Hex, "no_password_matched", nil)
		return nil, fmt.Errorf("%w: no password in the set opened this file", ErrRejected)
	}

	// --- stage 5: blob move (the last irreversible step) -------------------
	backupID := s.newID()
	blobPath := fmt.Sprintf("%s/%s.tryst", ownerID, backupID)

	stage, err := os.Open(stagePath)
	if err != nil {
		return nil, fmt.Errorf("ingest: reopen staged file: %w", err)
	}
	putSum, err := s.store.Put(ownerID, backupID, stage)
	_ = stage.Close()
	if err != nil {
		if errors.Is(err, blobstore.ErrBlobExists) {
			// Extremely unlikely (id collision), but if it happens the
			// operator hears about it — the fresh id we just generated is
			// worse than useless in that case.
			s.logger.Warn("ingest: blob id collision", "owner", ownerID, "id", backupID)
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("ingest: blobstore.Put: %w", err)
	}
	if !equalBytes(putSum, stageSHA) {
		// Impossible unless the tmpfs bytes changed between stage-hash and
		// Put-hash — but if it happens the blob on disk is not what we
		// think it is, which is a data-integrity failure worth screaming
		// about rather than swallowing.
		s.logger.Error("ingest: SHA disagreement between stage and Put",
			"owner", ownerID, "id", backupID,
			"stage_sha", hex.EncodeToString(stageSHA), "put_sha", hex.EncodeToString(putSum))
		return nil, fmt.Errorf("ingest: SHA disagreement between stage (%x) and Put (%x)",
			stageSHA, putSum)
	}

	// --- stage 6: index insert + password touch + event, in one tx ---------
	res, err := s.recordSuccess(ownerID, backupID, source, filename, blobPath, sha256Hex,
		stageSize, manifest, winnerID)
	if err != nil {
		// The blob is on disk but the index insert failed. It is now an
		// orphan — log prominently so an operator can reconcile.
		s.logger.Error("ingest: index insert failed, blob is orphaned",
			"owner", ownerID, "id", backupID, "sha", sha256Hex[:16], "blob_path", blobPath,
			"err", err)
		return nil, err
	}

	if s.onCommit != nil {
		s.onCommit()
	}
	s.logger.Info("ingest ok",
		"owner", ownerID, "id", backupID, "sha", sha256Hex[:16],
		"source", source, "schema", manifest.TrystSchemaVersion,
		"opened_by", winnerID)
	return res, nil
}

// --- pipeline helpers -------------------------------------------------------

// stageInput copies r to a tmpfs file, hashing along the way and bounding at
// trystbk.MaxBackupBytes with a one-byte overflow probe.
func (s *Service) stageInput(r io.Reader) (path string, sha []byte, size int64, err error) {
	if err := os.MkdirAll(s.tmpDir, 0o700); err != nil {
		return "", nil, 0, fmt.Errorf("ingest: mkdir tmpfs: %w", err)
	}
	f, err := os.CreateTemp(s.tmpDir, "ingest-*.tmp")
	if err != nil {
		return "", nil, 0, fmt.Errorf("ingest: create staging: %w", err)
	}
	stagePath := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(stagePath)
		}
	}()

	h := sha256.New()
	// Copy up to MaxBackupBytes; then probe for one extra byte to distinguish
	// "we bounded it" from "the file ended exactly at the cap".
	limited := io.LimitReader(r, int64(trystbk.MaxBackupBytes))
	n, err := io.Copy(io.MultiWriter(f, h), limited)
	if err != nil {
		return "", nil, 0, fmt.Errorf("ingest: stage copy: %w", err)
	}
	var probe [1]byte
	if extra, _ := r.Read(probe[:]); extra > 0 {
		return "", nil, 0, fmt.Errorf("%w: input exceeds MaxBackupBytes (%d)", ErrRejected, trystbk.MaxBackupBytes)
	}
	if err := f.Sync(); err != nil {
		return "", nil, 0, fmt.Errorf("ingest: sync staging: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", nil, 0, fmt.Errorf("ingest: close staging: %w", err)
	}
	cleanup = false
	return stagePath, h.Sum(nil), n, nil
}

// headerProbe rejects obviously wrong files before any KDF work.
func (s *Service) headerProbe(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = trystbk.ParseHeader(f)
	return err
}

// findDuplicate returns the id of an existing backup with the same SHA for
// this owner, or "" if there is none.
func (s *Service) findDuplicate(ownerID, sha256Hex string) (string, error) {
	var id string
	err := s.idx.DB().QueryRow(
		`SELECT id FROM backup WHERE owner_id = ? AND sha256 = ?`,
		ownerID, sha256Hex).Scan(&id)
	if err != nil {
		if errors.Is(err, index.ErrNotFound) {
			return "", nil
		}
		// sql.ErrNoRows path — treat as no duplicate.
		if err.Error() == "sql: no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

// trialDecrypt walks the password set. Returns (manifest, winner_password_id,
// nil) on the first opener. Returns (nil, "", nil) if none matched — the
// caller distinguishes this from a structural failure by winner == "".
// Returns (nil, "", err) for a structural rejection surfaced by trystbk.
func (s *Service) trialDecrypt(stagePath string, passwords []index.BackupPassword) (
	*trystbk.Manifest, string, error,
) {
	for _, p := range passwords {
		f, err := os.Open(stagePath)
		if err != nil {
			return nil, "", err
		}
		m, err := trystbk.Open(f, string(p.Passphrase))
		_ = f.Close()
		if err == nil {
			return m, p.ID, nil
		}
		if errors.Is(err, trystbk.ErrWrongPassword) {
			continue
		}
		// Anything else is structural (bad ZIP, missing data.json, oversize,
		// header truncation). No point trying more passwords.
		return nil, "", err
	}
	return nil, "", nil
}

// recordSuccess writes the backup row + counts + event + password touch in a
// single transaction. Returns the caller-facing Result.
func (s *Service) recordSuccess(
	ownerID, backupID string, source Source, filename, blobPath, sha256Hex string,
	size int64, m *trystbk.Manifest, winnerPasswordID string,
) (*Result, error) {
	tx, err := s.idx.DB().Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	ingestedAt := s.now().Unix()
	verifiedAt := ingestedAt

	var trystSchemaV any
	if m.TrystSchemaVersion > 0 {
		trystSchemaV = m.TrystSchemaVersion
	}

	if _, err := tx.Exec(
		`INSERT INTO backup
		 (id, owner_id, sha256, size_bytes, ingested_at, source, original_filename,
		  container_version, kdf_iterations, tryst_schema_version, verified_at,
		  verify_status, opened_by_password_id, blob_path)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		backupID, ownerID, sha256Hex, size, ingestedAt, string(source), filename,
		m.Version, m.Iterations, trystSchemaV, verifiedAt,
		"ok", winnerPasswordID, blobPath,
	); err != nil {
		return nil, fmt.Errorf("insert backup: %w", err)
	}

	// backup_table_count: every row from Manifest.TableCounts, with __media__
	// carrying MediaBytes in total_bytes (D-15).
	for name, count := range m.TableCounts {
		var totalBytes any
		if name == trystbk.SyntheticMediaKey && m.MediaBytes > 0 {
			totalBytes = m.MediaBytes
		}
		if _, err := tx.Exec(
			`INSERT INTO backup_table_count(backup_id, table_name, row_count, total_bytes)
			 VALUES (?,?,?,?)`,
			backupID, name, count, totalBytes,
		); err != nil {
			return nil, fmt.Errorf("insert table_count %q: %w", name, err)
		}
	}

	if _, err := tx.Exec(
		`UPDATE owner_backup_password SET last_used_at = ? WHERE id = ?`,
		ingestedAt, winnerPasswordID,
	); err != nil {
		return nil, fmt.Errorf("touch password: %w", err)
	}

	// Neutral event detail (N15) — hash prefix + winner id, never content.
	detail := fmt.Sprintf("sha=%s opened_by=%s", sha256Hex[:16], winnerPasswordID)
	if _, err := tx.Exec(
		`INSERT INTO event(at, owner_id, kind, detail) VALUES (?,?,?,?)`,
		ingestedAt, ownerID, "ingest_ok", detail,
	); err != nil {
		return nil, fmt.Errorf("log event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Build the caller-facing result. Copy the table counts so the caller
	// cannot mutate our Manifest reference.
	counts := make(map[string]int, len(m.TableCounts))
	for k, v := range m.TableCounts {
		counts[k] = v
	}
	return &Result{
		BackupID:           backupID,
		SHA256:             sha256Hex,
		SizeBytes:          size,
		TrystSchemaVersion: m.TrystSchemaVersion,
		TableCounts:        counts,
		OpenedByPasswordID: winnerPasswordID,
	}, nil
}

// logRejected writes an event row with a neutral detail (hash prefix +
// reason code) — no encounter content, no passwords, no filenames beyond
// what the operator already sees.
func (s *Service) logRejected(ownerID, sha256Hex, reason string, cause error) {
	shaPrefix := sha256Hex
	if len(shaPrefix) > 16 {
		shaPrefix = shaPrefix[:16]
	}
	detail := fmt.Sprintf("sha=%s reason=%s", shaPrefix, reason)
	_ = s.idx.LogEvent(s.now().Unix(), ownerID, "ingest_rejected", detail)
	if cause != nil {
		s.logger.Warn("ingest rejected",
			"owner", ownerID, "sha", shaPrefix, "reason", reason, "err", cause.Error())
	} else {
		s.logger.Warn("ingest rejected", "owner", ownerID, "sha", shaPrefix, "reason", reason)
	}
}

// --- small helpers ----------------------------------------------------------

// defaultIDGen returns a monotonic-shaped hex id generator. Not a ULID (this
// package must not add a ULID dependency for what is effectively a test
// scaffold); production wires in a real ULID generator via Options.NewID.
func defaultIDGen() IDGenerator {
	var seq uint64
	return func() string {
		seq++
		ts := time.Now().UnixNano()
		return fmt.Sprintf("%016x%08x", uint64(ts), seq)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
