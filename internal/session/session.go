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
// Package session manages Sanctum's owner-login sessions.
//
// Sessions live in process RAM — not tmpfs, not the sealed index. This is
// intentional: RAM dies with the process, which is STRONGER than tmpfs
// (which technically survives a `docker restart -f` if inode caching pins
// the file). A container restart re-locks the vault (D-4); a re-lock
// invalidates every issued session (N17). Both of these are enforced by
// Clear() being called from vault.Vault.Lock().
//
// Session IDs are 32 random bytes, base64url-encoded. That is a search
// space of 2^256, so an attacker on the LAN (T1/T2) guessing session
// cookies is not a realistic threat compared to the vault-unlock and
// owner-login KDF walls in front of them.
//
// ADR D-17 fixes the TTLs: 30-minute IDLE timeout (rolling; bumped on
// every authenticated request), 12-hour ABSOLUTE maximum (from Issue
// time, not extendable).
package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Config sets the two TTLs. Zero values are interpreted as "use the D-17
// defaults" in NewManager; a caller that wants a genuinely shorter TTL
// passes the exact duration.
type Config struct {
	IdleTTL time.Duration
	MaxTTL  time.Duration
}

// DefaultConfig returns the D-17 defaults.
func DefaultConfig() Config {
	return Config{
		IdleTTL: 30 * time.Minute,
		MaxTTL:  12 * time.Hour,
	}
}

// Session is one issued cookie's server-side record.
type Session struct {
	ID        string
	OwnerID   string
	RemoteIP  string
	CreatedAt time.Time
	LastSeen  time.Time
}

// ManagerOptions configure NewManager. Both fields are optional; sensible
// defaults are used when omitted.
type ManagerOptions struct {
	Config Config
	Now    func() time.Time
	Logger *slog.Logger
}

// Manager holds the sessions map and its TTLs. Safe for concurrent use.
type Manager struct {
	cfg    Config
	now    func() time.Time
	logger *slog.Logger

	mu   sync.Mutex
	byID map[string]*Session
}

// Well-known errors.
var (
	ErrNotFound = errors.New("session: not found")
	ErrExpired  = errors.New("session: expired")
)

// NewManager wires a Manager. Fails on obviously-broken configs.
func NewManager(opt ManagerOptions) (*Manager, error) {
	cfg := opt.Config
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 12 * time.Hour
	}
	if cfg.IdleTTL > cfg.MaxTTL {
		return nil, fmt.Errorf("session: IdleTTL %v > MaxTTL %v", cfg.IdleTTL, cfg.MaxTTL)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	return &Manager{
		cfg:    cfg,
		now:    opt.Now,
		logger: opt.Logger,
		byID:   map[string]*Session{},
	}, nil
}

// Config returns the effective config (defaults applied).
func (m *Manager) Config() Config { return m.cfg }

// Issue mints a fresh session for ownerID and returns it. remoteIP is
// recorded for the audit trail; it is NOT bound into the cookie (a mobile
// device that roams between IPs must not be logged out on every hop).
func (m *Manager) Issue(ownerID, remoteIP string) (*Session, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	now := m.now()
	s := &Session{
		ID:        id,
		OwnerID:   ownerID,
		RemoteIP:  remoteIP,
		CreatedAt: now,
		LastSeen:  now,
	}
	m.mu.Lock()
	m.byID[id] = s
	m.mu.Unlock()
	return s, nil
}

// Get looks up a session and returns it if valid. Updates LastSeen (the
// rolling IDLE bump). Returns ErrNotFound for unknown ids and ErrExpired
// for known-but-expired.
//
// Expired sessions are removed from the map here — Get is called on every
// authenticated request, so this doubles as opportunistic GC.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	now := m.now()
	if now.Sub(s.LastSeen) > m.cfg.IdleTTL || now.Sub(s.CreatedAt) > m.cfg.MaxTTL {
		delete(m.byID, id)
		return nil, ErrExpired
	}
	s.LastSeen = now
	// Return a copy so callers cannot silently mutate the stored record.
	cp := *s
	return &cp, nil
}

// Delete removes one session (logout).
func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
}

// Clear removes every session. Called from vault.Lock (N17).
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Rebuild the map so we do not accidentally leak references to the old
	// Session values through some other goroutine holding a range iterator.
	m.byID = map[string]*Session{}
}

// GC drops every expired session. Called on a timer by the caller; Get()
// prunes on the fly, so this is a "clean up ancient sessions no one has
// touched" pass rather than a critical guarantee.
func (m *Manager) GC() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	removed := 0
	for id, s := range m.byID {
		if now.Sub(s.LastSeen) > m.cfg.IdleTTL || now.Sub(s.CreatedAt) > m.cfg.MaxTTL {
			delete(m.byID, id)
			removed++
		}
	}
	return removed
}

// Count returns how many live sessions the manager holds. Test-facing.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}

// generateID produces a base64url-encoded 32-byte random id. 2^256 space
// makes cookie guessing not a realistic threat.
func generateID() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
