package index

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/trystbk"
)

// RebuildResult reports what Rebuild recovered and what it could not.
type RebuildResult struct {
	// BackupsRecovered is the number of `backup` rows inserted.
	BackupsRecovered int
	// BlobsSkipped counts blobs whose SHA-256 did not match the sidecar or
	// whose header failed to parse. Details go to the returned index's event
	// log (kind = "rebuild_skipped_blob").
	BlobsSkipped int
	// BlobsUnopenable counts blobs that verified structurally but that no
	// provided password could open. They stay on disk (immutable, D-11); the
	// operator can add more passwords and rerun.
	BlobsUnopenable int
	// Owners is the list of owner ids the rebuild encountered on disk. The
	// operator must re-provision `owner` rows (label + login credentials)
	// and `owner_backup_password` entries — those live only in the sealed
	// index and are lost with it (documented in RUNBOOK.md).
	Owners []string
}

// ErrRebuildNoPasswords surfaces when Rebuild has been asked to reindex a
// non-empty vault but the caller provided no candidate passwords.
var ErrRebuildNoPasswords = errors.New("index/rebuild: no candidate passwords given — nothing can be opened")

// Rebuild reconstructs the recoverable subset of an index from a blob store,
// using the provided candidate passwords for trial decrypt.
//
// What IS recovered: `backup` rows (with SHA-256, size, container version,
// KDF iterations, tryst schema version), the `backup_table_count` rows for
// each (including the D-15 __media__ synthetic row), and one `event` per
// action taken.
//
// What is NOT recovered: `owner.label`, `owner.login_*`, and
// `owner_backup_password` entries. These live only in the sealed index
// (DATA_MODEL), so a rebuild is not a full restore — it recovers the
// bookkeeping that could otherwise be re-derived from the blobs. The
// operator re-provisions credentials manually against the recovered
// `backup.owner_id` values.
//
// The candidate passwords are supplied ONE LEVEL UP because Rebuild does not
// know which password belongs to which owner: it tries each provided secret
// against each blob. This is O(owners × blobs × passwords) trial-decrypts
// and is fine for real vault sizes; it is meant for disaster recovery, not
// a hot path.
func Rebuild(store *blobstore.Store, candidates []string, now func() time.Time) (*Index, *RebuildResult, error) {
	if now == nil {
		now = time.Now
	}
	if len(candidates) == 0 {
		// Empty vault is fine; a populated vault with no candidates is not.
		owners, err := store.ListOwners()
		if err != nil {
			return nil, nil, err
		}
		hasAnyBlob := false
		for _, o := range owners {
			es, err := store.List(o)
			if err != nil {
				return nil, nil, err
			}
			if len(es) > 0 {
				hasAnyBlob = true
				break
			}
		}
		if hasAnyBlob {
			return nil, nil, ErrRebuildNoPasswords
		}
	}

	idx, err := OpenInMemory()
	if err != nil {
		return nil, nil, err
	}
	res := &RebuildResult{}

	owners, err := store.ListOwners()
	if err != nil {
		_ = idx.Close()
		return nil, nil, err
	}
	res.Owners = owners

	for _, owner := range owners {
		// Insert a placeholder owner row so the backup FK holds. The
		// credentials are RANDOM bytes — no passphrase can match them. This
		// is deliberate: it forces the operator to re-provision through the
		// explicit "reset credentials" path rather than silently inheriting
		// a placeholder identity. Placeholder rows are labelled so anyone
		// looking at the index knows what they are.
		if err := insertPlaceholderOwner(idx, owner, now); err != nil {
			_ = idx.Close()
			return nil, nil, fmt.Errorf("placeholder owner %q: %w", owner, err)
		}

		entries, err := store.List(owner)
		if err != nil {
			_ = idx.Close()
			return nil, nil, err
		}
		for _, e := range entries {
			// Verify the on-disk bytes before touching the crypto.
			if err := store.Verify(owner, e.ID); err != nil {
				res.BlobsSkipped++
				_ = idx.LogEvent(now().Unix(), owner, "rebuild_skipped_blob",
					fmt.Sprintf("id=%s sha256=%x reason=verify_failed", e.ID, e.SHA256[:4]))
				continue
			}

			opened, headerVer, kdfIters, tsv, tableCounts, err := trialOpen(store, owner, e.ID, candidates)
			if err != nil {
				res.BlobsSkipped++
				_ = idx.LogEvent(now().Unix(), owner, "rebuild_skipped_blob",
					fmt.Sprintf("id=%s reason=%v", e.ID, err))
				continue
			}
			if !opened {
				res.BlobsUnopenable++
				_ = idx.LogEvent(now().Unix(), owner, "rebuild_skipped_blob",
					fmt.Sprintf("id=%s reason=no_password_matched", e.ID))
				continue
			}

			backup := Backup{
				ID:                 e.ID,
				OwnerID:            owner,
				SHA256:             fmt.Sprintf("%x", e.SHA256),
				SizeBytes:          e.Size,
				IngestedAt:         now().Unix(),
				Source:             "rebuild",
				ContainerVersion:   headerVer,
				KDFIterations:      kdfIters,
				TrystSchemaVersion: intPtr(tsv),
				VerifyStatus:       "ok",
				BlobPath:           fmt.Sprintf("%s/%s.tryst", owner, e.ID),
			}
			t := now().Unix()
			backup.VerifiedAt = &t

			if err := idx.InsertBackup(backup, tableCounts); err != nil {
				_ = idx.Close()
				return nil, nil, fmt.Errorf("insert rebuilt backup %s/%s: %w", owner, e.ID, err)
			}
			res.BackupsRecovered++
		}
	}

	return idx, res, nil
}

// trialOpen tries every candidate password against a single blob until one
// authenticates or all fail. Returns opened=false with err=nil for the
// specific "no password matched" case, so the caller can log it separately
// from a structural failure.
func trialOpen(store *blobstore.Store, owner, id string, candidates []string) (
	opened bool, headerVersion int, kdfIterations int, trystSchema int,
	tableCounts map[string]TableCount, err error,
) {
	for _, pw := range candidates {
		r, gerr := store.Get(owner, id)
		if gerr != nil {
			return false, 0, 0, 0, nil, gerr
		}
		m, oerr := trystbk.Open(r, pw)
		// Drain the reader (defence against a code path that returned early).
		_, _ = io.Copy(io.Discard, r)
		_ = r.Close()
		if oerr != nil {
			if isWrongPassword(oerr) {
				continue // try the next password
			}
			// A structural failure: header truncation, malformed ZIP, missing
			// data.json. This blob cannot be indexed with any password.
			return false, 0, 0, 0, nil, oerr
		}
		tc := map[string]TableCount{}
		for name, count := range m.TableCounts {
			tc[name] = TableCount{RowCount: count}
		}
		if m.MediaBytes > 0 || m.TableCounts[trystbk.SyntheticMediaKey] > 0 {
			// Attach the byte total to the __media__ synthetic row (D-15).
			mb := m.MediaBytes
			tc[trystbk.SyntheticMediaKey] = TableCount{
				RowCount:   m.TableCounts[trystbk.SyntheticMediaKey],
				TotalBytes: &mb,
			}
		}
		return true, m.Version, m.Iterations, m.TrystSchemaVersion, tc, nil
	}
	return false, 0, 0, 0, nil, nil
}

func isWrongPassword(err error) bool {
	return errors.Is(err, trystbk.ErrWrongPassword)
}

func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// insertPlaceholderOwner adds a row for ownerID with random, unusable login
// credentials. The label makes the state obvious in any UI or log.
func insertPlaceholderOwner(idx *Index, ownerID string, now func() time.Time) error {
	salt := make([]byte, 16)
	hash := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(hash); err != nil {
		return err
	}
	return idx.CreateOwner(
		Owner{
			ID:            ownerID,
			Label:         "<unrecovered — re-provision credentials>",
			LoginUsername: "rebuild-" + ownerID,
			CreatedAt:     now().Unix(),
		},
		OwnerAuth{
			KDF:        "pbkdf2-sha256",
			Salt:       salt,
			Iterations: 600_000,
			Hash:       hash, // random bytes: cannot match any passphrase
		},
	)
}
