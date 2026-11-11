package session

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
	"errors"
	"log/slog"
	"testing"
	"time"
)

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func mustNewManager(t *testing.T, now func() time.Time, cfg Config) *Manager {
	t.Helper()
	m, err := NewManager(ManagerOptions{Config: cfg, Now: now, Logger: nullLogger()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestIssue_ReturnsUniqueIDs(t *testing.T) {
	m := mustNewManager(t, time.Now, DefaultConfig())
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := m.Issue("O", "1.2.3.4")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate session id: %s", s.ID)
		}
		seen[s.ID] = true
	}
	if m.Count() != 100 {
		t.Errorf("Count = %d, want 100", m.Count())
	}
}

func TestGet_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	m := mustNewManager(t, clock, DefaultConfig())

	s, _ := m.Issue("OWNER1", "1.1.1.1")
	got, err := m.Get(s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OwnerID != "OWNER1" {
		t.Errorf("OwnerID = %q, want OWNER1", got.OwnerID)
	}
}

func TestGet_UnknownIDReturnsErrNotFound(t *testing.T) {
	m := mustNewManager(t, time.Now, DefaultConfig())
	if _, err := m.Get("no-such-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A session that has not been Get()-touched within IdleTTL is expired.
func TestGet_IdleExpiry(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	nowRef := t0
	clock := func() time.Time { return nowRef }
	m := mustNewManager(t, clock, Config{IdleTTL: 5 * time.Minute, MaxTTL: 1 * time.Hour})

	s, _ := m.Issue("O", "")
	nowRef = t0.Add(6 * time.Minute)
	if _, err := m.Get(s.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	// And it is gone (Get prunes).
	if _, err := m.Get(s.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Get: err = %v, want ErrNotFound", err)
	}
}

// A session that gets bumped stays alive right at the idle boundary.
func TestGet_BumpsLastSeen(t *testing.T) {
	// Keep a stable baseline `t0`; the clock reads from `nowRef` which the
	// test moves forward relative to t0. Do NOT rewrite t0 itself.
	t0 := time.Unix(1_700_000_000, 0)
	nowRef := t0
	clock := func() time.Time { return nowRef }
	m := mustNewManager(t, clock, Config{IdleTTL: 5 * time.Minute, MaxTTL: 1 * time.Hour})

	s, _ := m.Issue("O", "")
	nowRef = t0.Add(4 * time.Minute)
	if _, err := m.Get(s.ID); err != nil {
		t.Fatalf("Get at t+4min: %v", err)
	}
	// Another 4 minutes since the last Get keeps us alive (last-seen was bumped).
	nowRef = t0.Add(8 * time.Minute)
	if _, err := m.Get(s.ID); err != nil {
		t.Fatalf("Get at t+8min after bump: %v", err)
	}
	// But 6 minutes with no Get in between kills it.
	nowRef = t0.Add(14 * time.Minute)
	if _, err := m.Get(s.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("Get at t+14min (idle 6min since last): %v, want ErrExpired", err)
	}
}

// MaxTTL beats IdleTTL: a session that is bumped repeatedly, staying inside
// the idle window, STILL dies at the absolute max. This defends against a
// compromised cookie whose holder is actively using it.
func TestGet_AbsoluteMaxExpiry(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	nowRef := t0
	clock := func() time.Time { return nowRef }
	// IdleTTL >= bump cadence so idle never fires; MaxTTL is what should end it.
	// (The constructor requires IdleTTL <= MaxTTL, hence IdleTTL == MaxTTL here.)
	m := mustNewManager(t, clock, Config{IdleTTL: 10 * time.Minute, MaxTTL: 10 * time.Minute})

	s, _ := m.Issue("O", "")
	for i := 1; i <= 12; i++ {
		nowRef = t0.Add(time.Duration(i) * time.Minute)
		_, err := m.Get(s.ID)
		if i <= 10 {
			if err != nil {
				t.Errorf("Get at t+%dmin: %v, want ok", i, err)
			}
		} else {
			if !errors.Is(err, ErrExpired) {
				t.Errorf("Get at t+%dmin: %v, want ErrExpired (past MaxTTL)", i, err)
			}
			break
		}
	}
}

// N17: Clear invalidates every issued session.
func TestClear_InvalidatesEverything(t *testing.T) {
	m := mustNewManager(t, time.Now, DefaultConfig())
	ids := []string{}
	for i := 0; i < 5; i++ {
		s, _ := m.Issue("O", "")
		ids = append(ids, s.ID)
	}
	m.Clear()
	if m.Count() != 0 {
		t.Errorf("Count after Clear = %d, want 0", m.Count())
	}
	for _, id := range ids {
		if _, err := m.Get(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %s survived Clear: err = %v", id, err)
		}
	}
}

func TestDelete_Logout(t *testing.T) {
	m := mustNewManager(t, time.Now, DefaultConfig())
	s, _ := m.Issue("O", "")
	m.Delete(s.ID)
	if _, err := m.Get(s.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete: err = %v, want ErrNotFound", err)
	}
}

func TestGC_PrunesExpired(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	nowRef := t0
	clock := func() time.Time { return nowRef }
	m := mustNewManager(t, clock, Config{IdleTTL: 5 * time.Minute, MaxTTL: 1 * time.Hour})

	for i := 0; i < 5; i++ {
		m.Issue("O", "")
	}
	nowRef = t0.Add(10 * time.Minute)
	removed := m.GC()
	if removed != 5 {
		t.Errorf("GC removed %d, want 5", removed)
	}
	if m.Count() != 0 {
		t.Errorf("Count after GC = %d, want 0", m.Count())
	}
}

func TestNewManager_RejectsBadConfig(t *testing.T) {
	_, err := NewManager(ManagerOptions{
		Config: Config{IdleTTL: 2 * time.Hour, MaxTTL: 30 * time.Minute},
	})
	if err == nil {
		t.Fatal("NewManager accepted IdleTTL > MaxTTL")
	}
}

// Returned Session must be a copy, not a live reference — otherwise the
// caller can silently extend LastSeen or overwrite OwnerID.
func TestGet_ReturnsCopy(t *testing.T) {
	m := mustNewManager(t, time.Now, DefaultConfig())
	s, _ := m.Issue("OWNER1", "1.2.3.4")
	got, _ := m.Get(s.ID)
	got.OwnerID = "MUTATED"
	got2, _ := m.Get(s.ID)
	if got2.OwnerID != "OWNER1" {
		t.Errorf("stored OwnerID mutated to %q via returned copy", got2.OwnerID)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
