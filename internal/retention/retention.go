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
// Package retention decides which backups to prune from a Sanctum vault, and
// carries out the pruning through the index + blob store — never silently.
//
// The rule is small enough to state whole: **keep the newest N backups per
// owner AND everything younger than MaxAge**. Two backups only fall through
// to prune when *both* say they can go. A backup that is the newest for its
// owner is never pruned, regardless of age — an all-old vault is still a
// vault, and a policy that empties one is a bug.
//
// The decide/apply split is deliberate: `Decide` is a pure function that
// takes rows + policy + clock and returns two lists (keep, prune). Every
// consequence is testable in isolation; `Apply` is the thin layer that
// actually deletes and logs. A dry-run is `Decide` with `Apply` skipped.
package retention

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
)

// Policy names how many backups to retain and how old is "too old". A zero
// KeepMin means "no minimum count" (only MaxAge applies); a zero MaxAge
// means "age is not a criterion" (only KeepMin applies). Both zero => the
// policy prunes nothing.
type Policy struct {
	KeepMin int           // keep at least the newest N per owner (0 = unlimited)
	MaxAge  time.Duration // older than this AND beyond KeepMin => prune (0 = disabled)
}

// Decision describes what would happen to one backup. The Reason string is
// stable and used verbatim as the event detail suffix.
type Decision struct {
	Backup index.Backup
	Prune  bool
	Reason string
}

// Decide sorts backups newest-first, then walks the list applying the policy.
// Returns per-backup decisions in the same newest-first order.
//
// Ordering matters — pruning "the older duplicate" is meaningless without a
// canonical newest, and IngestedAt is Sanctum's clock, not a timestamp from
// inside the backup (DATA_MODEL). A backup with `IngestedAt == 0` is treated
// as ancient (Unix epoch), which is the pessimistic interpretation.
func Decide(backups []index.Backup, policy Policy, now time.Time) []Decision {
	if len(backups) == 0 {
		return nil
	}
	sorted := make([]index.Backup, len(backups))
	copy(sorted, backups)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].IngestedAt > sorted[j].IngestedAt
	})

	out := make([]Decision, 0, len(sorted))
	nowUnix := now.Unix()
	for i, b := range sorted {
		d := Decision{Backup: b}
		switch {
		case i == 0:
			d.Reason = "newest"
		case policy.KeepMin > 0 && i < policy.KeepMin:
			d.Reason = "within_keep_min"
		case policy.MaxAge > 0 && (nowUnix-b.IngestedAt) < int64(policy.MaxAge.Seconds()):
			d.Reason = "within_max_age"
		case policy.KeepMin == 0 && policy.MaxAge == 0:
			d.Reason = "policy_prunes_nothing"
		default:
			d.Prune = true
			d.Reason = "beyond_policy"
		}
		out = append(out, d)
	}
	return out
}

// Deleter is what Apply calls to remove a blob. blobstore.Store does not yet
// have a delete method (blobs have been immutable in every prior milestone);
// this interface lets tests fake it and lets retention be the ONLY caller of
// the real Delete when it lands. Kept small on purpose.
type Deleter interface {
	Delete(ownerID, id string) error
}

// Options bundles the collaborators Apply needs.
type Options struct {
	Store  Deleter
	Index  *index.Index
	Now    func() time.Time
	Logger *slog.Logger
}

// Apply carries out the prune decisions. Order per backup: delete blob →
// delete row → LogEvent(kind=pruned). Each backup is independent — one
// failure logs and moves on rather than aborting the batch (a jammed prune
// is more dangerous than a partial one: the operator would keep bumping
// against the limit).
//
// Returns the number of successfully pruned rows and the first error
// encountered (if any) for the caller to surface. Every failure is logged
// with the backup SHA prefix and the reason.
func Apply(decisions []Decision, ownerID string, opt Options) (int, error) {
	if opt.Store == nil || opt.Index == nil {
		return 0, errors.New("retention: Store and Index required")
	}
	logger := opt.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}

	var pruned int
	var firstErr error
	for _, d := range decisions {
		if !d.Prune {
			continue
		}
		shaPrefix := shortSHA(d.Backup.SHA256)
		if err := opt.Store.Delete(d.Backup.OwnerID, d.Backup.ID); err != nil {
			logger.Error("retention prune: blob delete failed",
				"sha", shaPrefix, "backup_id", d.Backup.ID, "err", err.Error())
			if firstErr == nil {
				firstErr = fmt.Errorf("delete blob %s: %w", d.Backup.ID, err)
			}
			continue
		}
		if _, err := opt.Index.DB().Exec(
			`DELETE FROM backup WHERE id = ?`, d.Backup.ID,
		); err != nil {
			logger.Error("retention prune: index delete failed",
				"sha", shaPrefix, "backup_id", d.Backup.ID, "err", err.Error())
			if firstErr == nil {
				firstErr = fmt.Errorf("delete backup row %s: %w", d.Backup.ID, err)
			}
			continue
		}
		detail := fmt.Sprintf("sha=%s reason=%s", shaPrefix, d.Reason)
		if err := opt.Index.LogEvent(now().Unix(), ownerID, "pruned", detail); err != nil {
			// Row + blob already gone — event failure should not roll back the
			// prune. Log loudly and continue.
			logger.Error("retention prune: event log failed",
				"sha", shaPrefix, "err", err.Error())
		}
		logger.Info("retention pruned", "sha", shaPrefix, "reason", d.Reason)
		pruned++
	}
	return pruned, firstErr
}

// shortSHA is the first 12 hex chars — enough to identify a blob in a log
// without dragging the whole hash across every line. Matches ingest's event
// detail convention.
func shortSHA(hex string) string {
	if len(hex) < 12 {
		return hex
	}
	return hex[:12]
}

// storeDeleter adapts *blobstore.Store to the Deleter interface once the
// real Delete method exists. Kept here so blobstore stays ignorant of the
// retention lifecycle.
type storeDeleter struct{ s *blobstore.Store }

func (d storeDeleter) Delete(ownerID, id string) error { return d.s.Delete(ownerID, id) }

// StoreDeleter wraps a *blobstore.Store for use with Apply.
func StoreDeleter(s *blobstore.Store) Deleter { return storeDeleter{s: s} }

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
