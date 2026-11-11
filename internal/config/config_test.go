package config

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

import "testing"

func TestLoadDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.Addr == "" || c.VaultDir == "" || c.TmpDir == "" || c.InboxDir == "" {
		t.Fatalf("Load() left a path or address empty: %+v", c)
	}
	if c.StalenessDays < 1 {
		t.Fatalf("StalenessDays = %d, want >= 1", c.StalenessDays)
	}
}

// The tmpfs path is what keeps decrypted data off the array (hard constraint 2).
// If it ever resolves to the vault dir, plaintext lands on persistent storage —
// so that has to be a startup failure, not a warning.
func TestLoadRejectsTmpDirEqualToVaultDir(t *testing.T) {
	t.Setenv("SANCTUM_VAULT_DIR", "/data/same")
	t.Setenv("SANCTUM_TMP_DIR", "/data/same")

	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded with TmpDir == VaultDir; want an error")
	}
}

func TestLoadRejectsBadStalenessDays(t *testing.T) {
	for _, v := range []string{"0", "-1", "banana"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("SANCTUM_STALENESS_DAYS", v)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted SANCTUM_STALENESS_DAYS=%q; want an error", v)
			}
		})
	}
}

// D12: the hour-valued alert settings accept 0 (disabled) or one minute to one
// year; anything else is refused rather than overflowing or truncating to 0.
func TestLoadHoursRange(t *testing.T) {
	for _, v := range []string{"0", "0.5", "24", "8760", "0.02"} {
		t.Setenv("SANCTUM_LOCKED_ALERT_AFTER_HOURS", v)
		if _, err := Load(); err != nil {
			t.Fatalf("Load() rejected SANCTUM_LOCKED_ALERT_AFTER_HOURS=%q: %v", v, err)
		}
	}
	for _, v := range []string{"0.0001", "8761", "1e12", "-1", "banana"} {
		t.Setenv("SANCTUM_LOCKED_ALERT_AFTER_HOURS", v)
		if _, err := Load(); err == nil {
			t.Fatalf("Load() accepted SANCTUM_LOCKED_ALERT_AFTER_HOURS=%q; want an error", v)
		}
		t.Setenv("SANCTUM_LOCKED_ALERT_AFTER_HOURS", "24")
		t.Setenv("SANCTUM_LOCKED_ALERT_DEBOUNCE_HOURS", v)
		if _, err := Load(); err == nil {
			t.Fatalf("Load() accepted SANCTUM_LOCKED_ALERT_DEBOUNCE_HOURS=%q; want an error", v)
		}
		t.Setenv("SANCTUM_LOCKED_ALERT_DEBOUNCE_HOURS", "24")
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
