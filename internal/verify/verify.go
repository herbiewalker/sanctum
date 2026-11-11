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
// Package verify runs Sanctum's periodic full re-verification of stored
// blobs (F15). "Verify" here means the same guarantee ingest gave us on the
// way in: the SHA-256 sidecar matches the blob AND a stored password
// actually decrypts the TRYSTBK1 stream. A blob that opens on read but not
// with any stored password is only half-verified — a partial verify is worse
// than no verify because it papers over the failure mode operators need to
// see (a lost passphrase is a lost backup, and staleness/prune decisions
// downstream must not treat an unopenable blob as a good backup).
//
// This package is read-only: it never modifies blobs. It updates
// backup.verify_status / verify_at on the index and emits verify_failed
// events on any failure — the operator's audit trail.
package verify

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/trystbk"
)

// Status values map to backup.verify_status (DATA_MODEL). Kept as constants
// so a typo becomes a compile error.
const (
	StatusOK             = "ok"
	StatusHashMismatch   = "hash_mismatch"
	StatusDecryptFailed  = "decrypt_failed"
	StatusPasswordAbsent = "password_absent" // no stored password could open it
)

// Result summarises one verify pass over one backup.
type Result struct {
	BackupID   string
	Status     string
	VerifiedAt int64
	Err        error // set for anything non-OK; message is safe (no passwords, no content)
}

// Service holds the collaborators. One per vault, held by the scheduler.
type Service struct {
	Store  *blobstore.Store
	Index  *index.Index
	Now    func() time.Time
	Logger *slog.Logger
}

// New constructs a Service with sensible defaults for Now/Logger.
func New(store *blobstore.Store, idx *index.Index, now func() time.Time, logger *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{Store: store, Index: idx, Now: now, Logger: logger}
}

// One runs the full verify pipeline against a single backup row. It tries
// the recorded opened_by_password_id first (single blob read), then falls
// back to walking the owner's password set (one blob read per attempt) —
// same walk ingest does, so a rotated password set is handled without
// operator intervention. If a fallback password wins, opened_by_password_id
// is updated so the next verify skips the walk.
func (s *Service) One(b index.Backup) Result {
	now := s.Now().Unix()
	r := Result{BackupID: b.ID, VerifiedAt: now}

	// First attempt: the recorded winner.
	if b.OpenedByPasswordID != nil && *b.OpenedByPasswordID != "" {
		var pw []byte
		err := s.Index.DB().QueryRow(
			`SELECT passphrase FROM owner_backup_password WHERE id = ?`,
			*b.OpenedByPasswordID,
		).Scan(&pw)
		if err == nil {
			status, openErr := s.attempt(b, pw)
			if status == StatusOK {
				s.updateStatus(b.ID, StatusOK, now)
				r.Status = StatusOK
				return r
			}
			if status == StatusHashMismatch {
				// A hash mismatch is definitive — a different password cannot
				// help. Record and return.
				r.Status = StatusHashMismatch
				r.Err = openErr
				s.record(b, r, "hash_mismatch")
				return r
			}
			// StatusDecryptFailed → fall through to walking the set.
		}
	}

	// Fallback: walk the owner's set. Order matches ingest (last_used_at DESC).
	passwords, err := s.Index.ListBackupPasswords(b.OwnerID)
	if err != nil {
		r.Status = StatusPasswordAbsent
		r.Err = err
		s.record(b, r, "password_lookup_failed")
		return r
	}
	if len(passwords) == 0 {
		r.Status = StatusPasswordAbsent
		r.Err = errors.New("no passwords stored for owner")
		s.record(b, r, "password_absent")
		return r
	}
	var lastStatus string = StatusDecryptFailed
	var lastErr error
	for _, p := range passwords {
		status, openErr := s.attempt(b, p.Passphrase)
		if status == StatusOK {
			s.updateStatus(b.ID, StatusOK, now)
			s.updateOpenedBy(b.ID, p.ID)
			r.Status = StatusOK
			return r
		}
		if status == StatusHashMismatch {
			r.Status = StatusHashMismatch
			r.Err = openErr
			s.record(b, r, "hash_mismatch")
			return r
		}
		lastStatus, lastErr = status, openErr
	}
	r.Status = lastStatus
	r.Err = lastErr
	s.record(b, r, "no_password_matched")
	return r
}

// attempt does one full read of the blob with one candidate password.
// Returns (StatusOK, nil), (StatusHashMismatch, err), or (StatusDecryptFailed, err).
func (s *Service) attempt(b index.Backup, pw []byte) (string, error) {
	rc, err := s.Store.Get(b.OwnerID, b.ID)
	if err != nil {
		return StatusHashMismatch, fmt.Errorf("blob open: %w", err)
	}
	_, openErr := trystbk.Open(rc, string(pw))
	// Drain any trailing bytes so Close's SHA covers the whole file.
	_, _ = io.Copy(io.Discard, rc)
	closeErr := rc.Close()

	if errors.Is(closeErr, blobstore.ErrHashMismatch) {
		return StatusHashMismatch, closeErr
	}
	if openErr != nil {
		return StatusDecryptFailed, openErr
	}
	if closeErr != nil {
		return StatusHashMismatch, closeErr
	}
	return StatusOK, nil
}

// All runs One over every backup for one owner.
func (s *Service) All(ownerID string) ([]Result, error) {
	backups, err := s.Index.ListBackups(ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(backups))
	for _, b := range backups {
		out = append(out, s.One(b))
	}
	return out, nil
}

// AllOwners runs One over every backup for every owner in the index.
func (s *Service) AllOwners() ([]Result, error) {
	rows, err := s.Index.DB().Query(`SELECT id FROM owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		owners = append(owners, id)
	}
	var all []Result
	for _, o := range owners {
		part, err := s.All(o)
		if err != nil {
			return all, err
		}
		all = append(all, part...)
	}
	return all, nil
}

func (s *Service) updateStatus(id, status string, at int64) {
	_, err := s.Index.DB().Exec(
		`UPDATE backup SET verify_status = ?, verified_at = ? WHERE id = ?`,
		status, at, id,
	)
	if err != nil {
		s.Logger.Error("verify: update status failed", "backup_id", id, "err", err.Error())
	}
}

func (s *Service) updateOpenedBy(backupID, passwordID string) {
	_, err := s.Index.DB().Exec(
		`UPDATE backup SET opened_by_password_id = ? WHERE id = ?`,
		passwordID, backupID,
	)
	if err != nil {
		s.Logger.Error("verify: update opened_by failed", "backup_id", backupID, "err", err.Error())
	}
}

func (s *Service) record(b index.Backup, r Result, reasonCode string) {
	s.updateStatus(b.ID, r.Status, r.VerifiedAt)
	detail := fmt.Sprintf("sha=%s reason=%s", shortSHA(b.SHA256), reasonCode)
	if err := s.Index.LogEvent(r.VerifiedAt, b.OwnerID, "verify_failed", detail); err != nil {
		s.Logger.Error("verify: log event failed", "backup_id", b.ID, "err", err.Error())
	}
	s.Logger.Warn("verify failed", "backup_id", b.ID, "reason", reasonCode)
}

func shortSHA(hex string) string {
	if len(hex) < 12 {
		return hex
	}
	return hex[:12]
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
