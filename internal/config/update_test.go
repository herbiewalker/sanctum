package config

import "testing"

func TestFractionalLockedAlertHours(t *testing.T) {
	t.Setenv("SANCTUM_LOCKED_ALERT_AFTER_HOURS", "0.02")
	c, err := Load()
	if err != nil {
		t.Fatalf("0.02 must be accepted (used to test-fire the alert on real hardware): %v", err)
	}
	if c.LockedAlertAfterHours != 0.02 {
		t.Fatalf("got %v", c.LockedAlertAfterHours)
	}
}

func TestBadHoursRejected(t *testing.T) {
	for _, v := range []string{"abc", "-1", "NaN", "Inf"} {
		t.Setenv("SANCTUM_LOCKED_ALERT_AFTER_HOURS", v)
		if _, err := Load(); err == nil {
			t.Fatalf("%q must be rejected", v)
		}
	}
}

func TestUpdateCheckDefaultsOffAndValidates(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.UpdateCheck {
		t.Fatal("update check must be opt-in")
	}
	t.Setenv("SANCTUM_UPDATE_CHECK", "true")
	t.Setenv("SANCTUM_UPDATE_CHECK_EVERY_HOURS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("an interval below 1 hour must be rejected")
	}
}
