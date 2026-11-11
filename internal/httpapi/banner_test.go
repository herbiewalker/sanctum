package httpapi

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// withConfig rebuilds the server over the same vault with a different config,
// so a banner can be tested against a chosen clock without sleeping.
func withConfig(t *testing.T, e *e2e, cfg Config) *e2e {
	t.Helper()
	cfg.Vault = Wrap(e.v)
	cfg.Logger = nullLogger()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := *e
	c.srv, c.mux = srv, srv.Routes()
	return &c
}

func TestLockedBanner(t *testing.T) {
	e := newE2E(t)
	now := time.Now()
	cases := []struct {
		name  string
		since int64
		want  bool
	}{
		{"locked for days", now.Add(-72 * time.Hour).Unix(), true},
		{"just locked", now.Add(-10 * time.Minute).Unix(), false},
		{"unknown", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			since := tc.since
			c := withConfig(t, e, Config{Now: func() time.Time { return now },
				LockedSince: func() int64 { return since }})
			html := do(t, c, "GET", "/", nil, nil).Body.String()
			got := strings.Contains(html, "has been locked for")
			if got != tc.want {
				t.Fatalf("banner=%v want %v\n%s", got, tc.want, html)
			}
		})
	}
}

func TestLockedBannerOmittedWhenNotConfigured(t *testing.T) {
	e := newE2E(t)
	if strings.Contains(do(t, e, "GET", "/", nil, nil).Body.String(), "has been locked for") {
		t.Fatal("no banner without a LockedSince source")
	}
}

func TestStaleBanner(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)
	do(t, e, "POST", "/passwords", url.Values{"label": {"default"}, "passphrase": {"the-backup-pw"}}, jar)
	rec := doUpload(t, e, "/upload", "foo.tryst", buildSyntheticBackup(t, "the-backup-pw", buildMinimalZip(t, 15)), jar)
	if rec.Code != 200 {
		t.Fatalf("upload: %d", rec.Code)
	}

	at := func(days int, threshold int) string {
		c := withConfig(t, e, Config{
			Now:           func() time.Time { return time.Now().Add(time.Duration(days) * 24 * time.Hour) },
			StalenessDays: threshold,
		})
		return do(t, c, "GET", "/status", nil, jar).Body.String()
	}
	if !strings.Contains(at(45, 30), "past your 30-day limit") {
		t.Fatal("a 45-day-old backup must warn against a 30-day limit")
	}
	if strings.Contains(at(1, 30), "past your") {
		t.Fatal("a fresh backup must not warn")
	}
	if strings.Contains(at(45, 0), "past your") {
		t.Fatal("threshold 0 disables the warning")
	}
}
