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
// Package scheduler is Sanctum's periodic worker loop. It runs three tasks
// on independent cadences:
//
//   - **Verify** (F15) — full re-verification of every stored blob. Only
//     runs while the vault is unlocked; skipped silently while locked.
//   - **Retention** — decides + prunes per owner. Only unlocked.
//   - **Staleness / locked-since alert** — emits notify intents. Runs in
//     BOTH states, because the whole point of the locked-since alert is to
//     surface an unattended-lock condition (R5, D-18).
//
// The scheduler has no state of its own beyond debounce timestamps for
// alerts; those live in vault/state.json so a restart cannot re-fire a
// recently sent notification. All indexed state is in the sealed index and
// only touched while unlocked.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/notify"
	"github.com/herbiewalker/sanctum/internal/retention"
	"github.com/herbiewalker/sanctum/internal/vault"
	"github.com/herbiewalker/sanctum/internal/verify"
)

// Config bundles the tunables. Zero values are legal and mean "skip this
// task"; the scheduler is opt-in per task.
type Config struct {
	// Cadences.
	VerifyEvery    time.Duration
	RetentionEvery time.Duration
	AlertEvery     time.Duration

	// Retention policy applied per owner.
	Retention retention.Policy

	// StalenessDefault is the default threshold used when owner.staleness_days
	// is NULL. Zero disables staleness evaluation while unlocked.
	StalenessDefault time.Duration

	// LockedAlertAfter fires the "locked since X" alert once the vault has
	// been locked longer than this. Zero disables the locked-since alert.
	LockedAlertAfter time.Duration

	// LockedAlertDebounce prevents re-firing "locked since X" more often
	// than this — survives restarts via state.json.
	LockedAlertDebounce time.Duration

	// TickInterval is the master loop cadence. Every task is only run when
	// its own interval has elapsed since its last run. Default: 1 minute.
	TickInterval time.Duration
}

// Options bundles the collaborators.
type Options struct {
	Vault    *vault.Vault
	Notifier notify.Notifier
	Now      func() time.Time
	Logger   *slog.Logger
}

// Service is the running scheduler.
type Service struct {
	cfg  Config
	vlt  *vault.Vault
	note notify.Notifier
	now  func() time.Time
	log  *slog.Logger

	// last-run timestamps (in-process; alert debounce persists via state).
	lastVerify    time.Time
	lastRetention time.Time
	lastAlert     time.Time
}

// New constructs a Service. Nil Notifier defaults to notify.NullNotifier.
func New(cfg Config, opt Options) (*Service, error) {
	if opt.Vault == nil {
		return nil, fmt.Errorf("scheduler: Vault required")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Notifier == nil {
		opt.Notifier = notify.NullNotifier{}
	}
	if cfg.TickInterval == 0 {
		cfg.TickInterval = time.Minute
	}
	return &Service{
		cfg: cfg, vlt: opt.Vault, note: opt.Notifier,
		now: opt.Now, log: opt.Logger,
	}, nil
}

// Run drives the loop until ctx is cancelled. Never returns an error — the
// scheduler logs and continues. Fatal-shaped conditions (vault absent,
// notifier configured badly) fail at New.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.TickInterval)
	defer t.Stop()
	// Run once immediately so a short-lived test / manual invocation sees
	// something happen without waiting a full interval.
	s.Tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick()
		}
	}
}

// Tick is the exposed single-pass helper — called by Run and by tests that
// prefer to drive the clock manually.
func (s *Service) Tick() {
	now := s.now()

	if s.cfg.AlertEvery > 0 && due(s.lastAlert, s.cfg.AlertEvery, now) {
		s.runAlerts(now)
		s.lastAlert = now
	}
	if !s.vlt.IsUnlocked() {
		return
	}
	if s.cfg.VerifyEvery > 0 && due(s.lastVerify, s.cfg.VerifyEvery, now) {
		s.runVerify(now)
		s.lastVerify = now
	}
	if s.cfg.RetentionEvery > 0 && due(s.lastRetention, s.cfg.RetentionEvery, now) {
		s.runRetention(now)
		s.lastRetention = now
	}
}

func due(last time.Time, every time.Duration, now time.Time) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= every
}

// runVerify walks every backup, updating verify_status + verified_at.
func (s *Service) runVerify(now time.Time) {
	idx := s.vlt.Index()
	if idx == nil {
		return
	}
	vs := verify.New(s.vlt.Store(), idx, s.now, s.log)
	results, err := vs.AllOwners()
	if err != nil {
		s.log.Error("scheduler: verify pass failed", "err", err.Error())
		return
	}
	ok, failed := 0, 0
	for _, r := range results {
		if r.Status == verify.StatusOK {
			ok++
		} else {
			failed++
			// One alert per failing backup — operator wants to know each.
			_ = s.note.Notify(notify.Intent{
				Severity: notify.SeverityWarning,
				Kind:     notify.KindVerifyFailed,
				Subject:  "Sanctum: backup verification failed",
				Body: fmt.Sprintf(
					"A stored backup failed re-verification (status=%s, backup_id=%s). "+
						"Check RUNBOOK 'verify_failed' section.",
					r.Status, r.BackupID,
				),
			})
		}
	}
	s.log.Info("scheduler: verify pass complete", "ok", ok, "failed", failed)
}

// runRetention decides + prunes per owner.
func (s *Service) runRetention(now time.Time) {
	idx := s.vlt.Index()
	if idx == nil {
		return
	}
	owners, err := listOwnerIDs(idx)
	if err != nil {
		s.log.Error("scheduler: retention list owners failed", "err", err.Error())
		return
	}
	var totalPruned int
	for _, o := range owners {
		backups, err := idx.ListBackups(o)
		if err != nil {
			s.log.Error("scheduler: retention list backups failed", "owner", o, "err", err.Error())
			continue
		}
		decisions := retention.Decide(backups, s.cfg.Retention, now)
		pruned, err := retention.Apply(decisions, o, retention.Options{
			Store: retention.StoreDeleter(s.vlt.Store()),
			Index: idx, Now: s.now, Logger: s.log,
		})
		if err != nil {
			s.log.Error("scheduler: retention apply partial failure",
				"owner", o, "pruned", pruned, "err", err.Error())
		}
		totalPruned += pruned
	}
	if totalPruned > 0 {
		_ = s.note.Notify(notify.Intent{
			Severity: notify.SeverityNormal,
			Kind:     notify.KindPruned,
			Subject:  "Sanctum: retention prune ran",
			Body:     fmt.Sprintf("Pruned %d backup(s) per retention policy.", totalPruned),
		})
	}
	s.log.Info("scheduler: retention pass complete", "pruned", totalPruned)
}

// runAlerts fires the two alert families that do NOT need the runtime key:
// staleness (unlocked-only, needs the index) and locked-since (locked-only,
// reads state.json). Callers hit this on every alert tick regardless of
// vault state.
func (s *Service) runAlerts(now time.Time) {
	if s.vlt.IsUnlocked() {
		s.runStaleness(now)
	} else {
		s.runLockedSinceAlert(now)
	}
}

func (s *Service) runStaleness(now time.Time) {
	if s.cfg.StalenessDefault <= 0 {
		return
	}
	idx := s.vlt.Index()
	if idx == nil {
		return
	}
	owners, err := listOwners(idx)
	if err != nil {
		s.log.Error("scheduler: staleness list owners failed", "err", err.Error())
		return
	}
	nowUnix := now.Unix()
	for _, o := range owners {
		threshold := s.cfg.StalenessDefault
		if o.StalenessDays != nil && *o.StalenessDays > 0 {
			threshold = time.Duration(*o.StalenessDays) * 24 * time.Hour
		}
		newest, err := newestBackup(idx, o.ID)
		if err != nil {
			s.log.Error("scheduler: staleness newest failed", "owner", o.ID, "err", err.Error())
			continue
		}
		var ageSec int64
		if newest == nil {
			// No backups yet — count from owner creation.
			ageSec = nowUnix - o.CreatedAt
		} else {
			ageSec = nowUnix - newest.IngestedAt
		}
		if time.Duration(ageSec)*time.Second < threshold {
			continue
		}
		days := int(ageSec / 86400)
		_ = s.note.Notify(notify.Intent{
			Severity:   notify.SeverityWarning,
			Kind:       notify.KindStaleness,
			Subject:    "Sanctum: owner backup is stale",
			OwnerLabel: o.Label,
			Body: fmt.Sprintf(
				"Newest backup for owner %q is %d days old (threshold %d days).",
				o.Label, days, int(threshold/(24*time.Hour)),
			),
		})
	}
}

func (s *Service) runLockedSinceAlert(now time.Time) {
	if s.cfg.LockedAlertAfter <= 0 {
		return
	}
	st, err := s.vlt.State()
	if err != nil {
		s.log.Error("scheduler: state load failed", "err", err.Error())
		return
	}
	if st.LockedSince == 0 {
		return
	}
	lockedFor := now.Sub(time.Unix(st.LockedSince, 0))
	if lockedFor < s.cfg.LockedAlertAfter {
		return
	}
	// Debounce across restarts.
	if s.cfg.LockedAlertDebounce > 0 && st.LastLockedAlertAt > 0 {
		since := now.Sub(time.Unix(st.LastLockedAlertAt, 0))
		if since < s.cfg.LockedAlertDebounce {
			return
		}
	}
	minutes := int(lockedFor.Minutes())
	err = s.note.Notify(notify.Intent{
		Severity: notify.SeverityAlert,
		Kind:     notify.KindLockedSince,
		Subject:  "Sanctum: vault has been locked",
		Body: fmt.Sprintf(
			"Vault locked since %s (%d minutes). Ingest and verify are paused until unlock.",
			time.Unix(st.LockedSince, 0).UTC().Format(time.RFC3339), minutes,
		),
	})
	if err != nil {
		s.log.Error("scheduler: locked-since notify failed", "err", err.Error())
		return
	}
	nowUnix := now.Unix()
	if err := s.vlt.UpdateState(func(x *vault.State) { x.LastLockedAlertAt = nowUnix }); err != nil {
		s.log.Error("scheduler: state update failed", "err", err.Error())
	}
}

// --- small index helpers kept here so the scheduler owns its own queries ---

func listOwnerIDs(idx *index.Index) ([]string, error) {
	rows, err := idx.DB().Query(`SELECT id FROM owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func listOwners(idx *index.Index) ([]index.Owner, error) {
	rows, err := idx.DB().Query(
		`SELECT id, label, login_username, created_at, staleness_days FROM owner`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []index.Owner
	for rows.Next() {
		var o index.Owner
		var staleness *int64
		if err := rows.Scan(&o.ID, &o.Label, &o.LoginUsername, &o.CreatedAt, &staleness); err != nil {
			return nil, err
		}
		if staleness != nil {
			v := int(*staleness)
			o.StalenessDays = &v
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func newestBackup(idx *index.Index, ownerID string) (*index.Backup, error) {
	backups, err := idx.ListBackups(ownerID)
	if err != nil {
		return nil, err
	}
	if len(backups) == 0 {
		return nil, nil
	}
	return &backups[0], nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
