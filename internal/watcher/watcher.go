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
// Package watcher polls Sanctum's inbox for stable TRYSTBK1 files and hands
// them to the ingest pipeline.
//
// Poll rather than fsnotify: at Sanctum's cadence (backups every few weeks
// per owner) fsnotify buys nothing but a dependency. A poll every N seconds
// is plenty responsive and drops the deps.
//
// "Stable" means the file's size has not changed for at least StabilitySeconds
// consecutive polls. This is what separates a file that Syncthing is still
// copying from one that fully arrived; ingesting a still-being-written file
// would fail parsing and count as a rejection, which is worse than waiting.
//
// The watcher only operates while UNLOCKED (D-4): Run returns when the caller's
// context is cancelled, and the caller is expected to cancel on re-lock.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/herbiewalker/sanctum/internal/ingest"
)

// Ingester is the surface Watcher needs from an ingest.Service — the whole
// Service is not needed, and taking the interface keeps this package testable
// without a full service wired up.
type Ingester interface {
	IngestFile(ownerID, path string) (*ingest.Result, error)
}

// Options configure a Watcher.
type Options struct {
	InboxDir  string // required — the directory to poll
	OwnerID   string // required — every file dropped here is attributed to this owner (v1 single-owner assumption)
	PollEvery time.Duration
	Stability time.Duration
	Logger    *slog.Logger
}

// Watcher scans an inbox directory. Not safe for concurrent Run calls — use
// one Watcher per inbox.
type Watcher struct {
	opt      Options
	ingester Ingester

	// seen tracks files currently being observed for stability. Key is the
	// absolute path; value is (last observed size, first-seen time, last-
	// changed time). A file whose size has been unchanged since a moment >=
	// Stability ago is ingested and removed from the map.
	seen map[string]sizeObs

	// done tracks files we have already handed off, whether they succeeded
	// or were rejected. Prevents re-ingest on the next poll cycle. Kept
	// alongside a "done at" timestamp so entries can eventually be pruned,
	// but v1 does not prune — the inbox is expected to be emptied by the
	// operator or by the source (Syncthing typically leaves files in place).
	done map[string]time.Time
}

type sizeObs struct {
	size        int64
	firstSeen   time.Time
	lastChanged time.Time
}

// New builds a Watcher. Fails on missing InboxDir/OwnerID/ingester.
func New(ingester Ingester, opt Options) (*Watcher, error) {
	if ingester == nil {
		return nil, errors.New("watcher: nil ingester")
	}
	if opt.InboxDir == "" {
		return nil, errors.New("watcher: InboxDir is required")
	}
	if opt.OwnerID == "" {
		return nil, errors.New("watcher: OwnerID is required")
	}
	if opt.PollEvery <= 0 {
		opt.PollEvery = 5 * time.Second
	}
	if opt.Stability <= 0 {
		opt.Stability = 2 * time.Second
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	return &Watcher{
		opt:      opt,
		ingester: ingester,
		seen:     map[string]sizeObs{},
		done:     map[string]time.Time{},
	}, nil
}

// Run polls until ctx is cancelled. Returns ctx.Err() on cancel; any other
// error from a single poll is logged and the loop continues (a transient
// filesystem error should not take the watcher down).
func (w *Watcher) Run(ctx context.Context) error {
	if err := os.MkdirAll(w.opt.InboxDir, 0o755); err != nil {
		return fmt.Errorf("watcher: mkdir inbox: %w", err)
	}
	w.opt.Logger.Info("watcher started",
		"inbox", w.opt.InboxDir, "owner", w.opt.OwnerID,
		"poll", w.opt.PollEvery, "stability", w.opt.Stability)

	// Do an initial pass immediately so a file already present at start is
	// not delayed by a full PollEvery interval.
	w.pollOnce(time.Now())

	t := time.NewTicker(w.opt.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.opt.Logger.Info("watcher stopped", "reason", ctx.Err().Error())
			return ctx.Err()
		case now := <-t.C:
			w.pollOnce(now)
		}
	}
}

// pollOnce is the state machine tick. Public via PollOnce for tests.
func (w *Watcher) pollOnce(now time.Time) {
	entries, err := os.ReadDir(w.opt.InboxDir)
	if err != nil {
		w.opt.Logger.Warn("watcher: readdir failed", "err", err.Error())
		return
	}

	present := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		// Only .tryst files are candidates. Syncthing writes temporary
		// files with weird prefixes/suffixes during transfer; ignoring
		// non-.tryst names avoids ingesting mid-transfer artefacts even
		// before the stability window kicks in.
		if filepath.Ext(e.Name()) != ".tryst" {
			continue
		}
		path := filepath.Join(w.opt.InboxDir, e.Name())
		present[path] = true

		// If we already ingested (or rejected) this path, skip it. The
		// operator or the source is expected to remove/rename the file if
		// they want it processed again.
		if _, ok := w.done[path]; ok {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			// File vanished between ReadDir and Stat — common during a
			// concurrent move. Drop from tracking.
			delete(w.seen, path)
			continue
		}

		obs, tracked := w.seen[path]
		switch {
		case !tracked:
			w.seen[path] = sizeObs{size: info.Size(), firstSeen: now, lastChanged: now}
		case obs.size != info.Size():
			obs.size = info.Size()
			obs.lastChanged = now
			w.seen[path] = obs
		default:
			// Size unchanged. Ingest once we've been quiet long enough.
			if now.Sub(obs.lastChanged) >= w.opt.Stability {
				w.handOff(path)
			}
		}
	}

	// Prune tracking for files that have disappeared from the inbox
	// entirely — otherwise `seen` grows forever across a churny inbox.
	for path := range w.seen {
		if !present[path] {
			delete(w.seen, path)
		}
	}
}

// PollOnce runs a single poll iteration. Exposed for tests so they can drive
// the state machine deterministically without waiting on a real ticker.
func (w *Watcher) PollOnce(now time.Time) { w.pollOnce(now) }

// handOff hands one file to the ingester and marks it done regardless of
// success — the operator is expected to remove or rename a rejected file
// before the watcher re-considers it, which mirrors how a human handles a
// failed inbox item.
func (w *Watcher) handOff(path string) {
	delete(w.seen, path)
	w.done[path] = time.Now()

	res, err := w.ingester.IngestFile(w.opt.OwnerID, path)
	if err != nil {
		w.opt.Logger.Warn("watcher: ingest rejected",
			"path", filepath.Base(path), "err", err.Error())
		return
	}
	// Log the SHA prefix defensively — production SHAs are 64 hex chars but
	// a truncated log line is far preferable to a panic if that ever changes.
	shaPrefix := res.SHA256
	if len(shaPrefix) > 16 {
		shaPrefix = shaPrefix[:16]
	}
	w.opt.Logger.Info("watcher: ingest ok",
		"path", filepath.Base(path), "backup_id", res.BackupID, "sha", shaPrefix)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
