package httpapi

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

// A simple per-key token bucket for rate-limiting authentication endpoints
// (unlock, owner-login), per N16.
//
// Deliberately not a full-featured limiter: no LRU eviction beyond a size
// cap, no distributed state, no Retry-After header calculation. The threat
// model is "an attacker on the LAN trying to brute-force a passphrase",
// which a bucket with capacity 5 and refill 1/minute reduces to a rate too
// slow to matter given Argon2id's per-attempt cost. If the map grows past
// maxTrackedKeys we drop the oldest — good enough at a household service
// scale, and cheaper than an LRU library.

import (
	"sync"
	"time"
)

// Config for a bucket.
type rateConfig struct {
	Capacity    int
	RefillEvery time.Duration
}

// Sensible defaults for the two auth endpoints. Unlock is stricter (one
// attempt per minute after the initial burst) because the vault passphrase
// is the root of everything; owner login is a bit more forgiving.
var (
	unlockRate = rateConfig{Capacity: 5, RefillEvery: 60 * time.Second}
	loginRate  = rateConfig{Capacity: 10, RefillEvery: 20 * time.Second}
)

const maxTrackedKeys = 4096

type bucket struct {
	tokens     int
	lastRefill time.Time
}

type limiter struct {
	cfg  rateConfig
	now  func() time.Time
	mu   sync.Mutex
	byIP map[string]*bucket
}

func newLimiter(cfg rateConfig, now func() time.Time) *limiter {
	if now == nil {
		now = time.Now
	}
	return &limiter{
		cfg:  cfg,
		now:  now,
		byIP: map[string]*bucket{},
	}
}

// Allow reports whether a request from key should be allowed and, if so,
// consumes one token. If the map has grown past maxTrackedKeys, one entry
// is deleted first (cheap defence against a scanner cycling through IPs).
func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.byIP[key]
	if !ok {
		if len(l.byIP) >= maxTrackedKeys {
			// Delete one arbitrary entry. Map range is randomised, so this
			// is not adversarially exploitable.
			for k := range l.byIP {
				delete(l.byIP, k)
				break
			}
		}
		b = &bucket{tokens: l.cfg.Capacity, lastRefill: now}
		l.byIP[key] = b
	}

	// Refill: one token per RefillEvery elapsed, capped at Capacity.
	elapsed := now.Sub(b.lastRefill)
	if elapsed > 0 && l.cfg.RefillEvery > 0 {
		add := int(elapsed / l.cfg.RefillEvery)
		if add > 0 {
			b.tokens += add
			if b.tokens > l.cfg.Capacity {
				b.tokens = l.cfg.Capacity
			}
			b.lastRefill = b.lastRefill.Add(time.Duration(add) * l.cfg.RefillEvery)
		}
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
