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
// Package config loads Sanctum's configuration from the environment only
// (12-Factor III).
//
// This package must never hold a secret. The vault passphrase is typed by a
// human at unlock and lives only in process memory (ADR D-4); it is not
// configuration, and any change that adds a password, key, or token field here
// violates hard constraint 3 in CLAUDE.md.
package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"time"
)

// Config is the complete runtime configuration. Paths, ports, thresholds —
// nothing sensitive.
type Config struct {
	// Addr is the listen address for the HTTP surface. LAN-only in v1 (D-12).
	Addr string

	// InboxDir is the watched drop folder that Syncthing/SMB/SAF deliver into.
	// Treated as fully untrusted input (THREAT_MODEL T6).
	InboxDir string

	// VaultDir holds the immutable TRYSTBK1 blobs and the sealed index. Lives
	// on the array; only ever contains ciphertext (hard constraint 2).
	VaultDir string

	// TmpDir is the tmpfs mount. The live SQLite index and any transient
	// decrypt buffer live here and die with the container.
	TmpDir string

	// AllowNonTmpfsTmpDir bypasses the runtime tmpfs check on TmpDir.
	// Set only on dev boxes / non-Linux hosts where a real tmpfs is not
	// available; never true in a real deployment (see hard constraint 2).
	AllowNonTmpfsTmpDir bool

	// StalenessDays is the global default before an owner's newest backup is
	// considered stale (F9). Per-owner overrides live in the index.
	StalenessDays int

	// ShutdownGrace bounds graceful shutdown: re-seal the index, zero the key,
	// exit (N11).
	ShutdownGrace time.Duration

	// NotifyDir is the drop directory D-18's dispatcher script watches.
	// Empty disables the notification channel entirely (a NullNotifier is
	// wired in that case).
	NotifyDir string

	// RetentionKeepMin keeps at least the newest N backups per owner
	// regardless of age. 0 = no minimum.
	RetentionKeepMin int

	// RetentionMaxAgeDays prunes backups older than this AND beyond the
	// keep-min. 0 = age is not a criterion.
	RetentionMaxAgeDays int

	// VerifyEveryHours drives the F15 re-verification pass. 0 = disabled.
	VerifyEveryHours int

	// RetentionEveryHours drives how often retention runs. 0 = disabled.
	RetentionEveryHours int

	// AlertEveryMinutes is how often the staleness / locked-since paths tick.
	AlertEveryMinutes int

	// LockedAlertAfterHours is the "vault has been locked" threshold. 0 = disabled.
	// Fractional values are allowed (0.02 ≈ 72 s) so the alert path can be
	// test-fired on real hardware without waiting an hour.
	LockedAlertAfterHours float64

	// LockedAlertDebounceHours prevents re-firing the locked-since alert more
	// often than this — survives restarts via state.json. 0 disables debounce.
	LockedAlertDebounceHours float64

	// NotifyURL is a comma-separated list of notification URLs (ntfy, Discord,
	// Slack, or a generic webhook; ADR D-20). The URL is a credential: it is
	// never logged or echoed. Empty = no URL channels.
	NotifyURL string

	// UpdateCheck enables the opt-in, read-only "is a newer release published?"
	// lookup against GitHub (ADR D-19). Off unless explicitly turned on.
	UpdateCheck bool

	// UpdateCheckEveryHours is the interval between lookups. Minimum 1.
	UpdateCheckEveryHours int
}

// Load reads the environment and applies defaults. It returns an error rather
// than falling back to a guess: a misconfigured path on this service means
// writing user data somewhere unintended.
func Load() (Config, error) {
	c := Config{
		Addr:          env("SANCTUM_ADDR", ":8080"),
		InboxDir:      env("SANCTUM_INBOX_DIR", "/data/inbox"),
		VaultDir:      env("SANCTUM_VAULT_DIR", "/data/vault"),
		TmpDir:        env("SANCTUM_TMP_DIR", "/tmp/sanctum"),
		NotifyDir:     env("SANCTUM_NOTIFY_DIR", ""),
		NotifyURL:     env("SANCTUM_NOTIFY_URL", ""),
		ShutdownGrace: 15 * time.Second,
	}

	days, err := envInt("SANCTUM_STALENESS_DAYS", 30)
	if err != nil {
		return Config{}, err
	}
	if days < 1 {
		return Config{}, fmt.Errorf("SANCTUM_STALENESS_DAYS must be >= 1, got %d", days)
	}
	c.StalenessDays = days

	if c.RetentionKeepMin, err = envInt("SANCTUM_RETENTION_KEEP_MIN", 3); err != nil {
		return Config{}, err
	}
	if c.RetentionMaxAgeDays, err = envInt("SANCTUM_RETENTION_MAX_AGE_DAYS", 365); err != nil {
		return Config{}, err
	}
	if c.VerifyEveryHours, err = envInt("SANCTUM_VERIFY_EVERY_HOURS", 168); err != nil {
		return Config{}, err
	}
	if c.RetentionEveryHours, err = envInt("SANCTUM_RETENTION_EVERY_HOURS", 24); err != nil {
		return Config{}, err
	}
	if c.AlertEveryMinutes, err = envInt("SANCTUM_ALERT_EVERY_MINUTES", 60); err != nil {
		return Config{}, err
	}
	if c.LockedAlertAfterHours, err = envFloat("SANCTUM_LOCKED_ALERT_AFTER_HOURS", 24); err != nil {
		return Config{}, err
	}
	if c.LockedAlertDebounceHours, err = envFloat("SANCTUM_LOCKED_ALERT_DEBOUNCE_HOURS", 24); err != nil {
		return Config{}, err
	}
	c.UpdateCheck = envBool("SANCTUM_UPDATE_CHECK", false)
	if c.UpdateCheckEveryHours, err = envInt("SANCTUM_UPDATE_CHECK_EVERY_HOURS", 24); err != nil {
		return Config{}, err
	}
	if c.UpdateCheckEveryHours < 1 {
		return Config{}, fmt.Errorf("SANCTUM_UPDATE_CHECK_EVERY_HOURS must be >= 1, got %d", c.UpdateCheckEveryHours)
	}

	// Dev/test escape hatch for the tmpfs guard. Any non-empty, non-"0",
	// non-"false" value enables it. Deliberately not documented in the
	// operator-facing runbook — a real deployment must not need this.
	c.AllowNonTmpfsTmpDir = envBool("SANCTUM_ALLOW_NONTMPFS_TMPDIR", false)

	// The tmpfs path must not sit inside the vault: that would put plaintext on
	// the array the moment the mount was missing. Fail loudly rather than
	// silently degrade (hard constraint 2).
	if c.TmpDir == c.VaultDir {
		return Config{}, fmt.Errorf("SANCTUM_TMP_DIR must not equal SANCTUM_VAULT_DIR")
	}

	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	switch v {
	case "0", "false", "FALSE", "False", "no", "NO", "off", "OFF":
		return false
	}
	return true
}

func envFloat(key string, def float64) (float64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("%s: %q is not a non-negative number", key, v)
	}
	return f, nil
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
