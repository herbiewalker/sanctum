package updatecheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/notify"
)

type recorder struct {
	mu   sync.Mutex
	got  []notify.Intent
	fail bool
}

func (r *recorder) Notify(i notify.Intent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("drop dir unavailable")
	}
	r.got = append(r.got, i)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func serve(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	ua := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ua = r.Header.Get("User-Agent")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, ua
}

func newChecker(url, current string, n notify.Notifier) *Checker {
	return New(Options{Current: current, APIURL: url, Notifier: n,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) }})
}

const rel = `{"tag_name":"v0.2.0","html_url":"https://github.com/herbiewalker/sanctum/releases/tag/v0.2.0","draft":false,"prerelease":false}`

func TestNewerVersionNotifiesOnce(t *testing.T) {
	srv, ua := serve(t, 200, rel)
	rec := &recorder{}
	c := newChecker(srv.URL, "0.1.0", rec)

	info, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Newer || info.Latest != "v0.2.0" || info.URL == "" {
		t.Fatalf("unexpected info %+v", info)
	}
	if rec.count() != 1 {
		t.Fatalf("want 1 notification, got %d", rec.count())
	}
	if rec.got[0].Kind != notify.KindUpdate {
		t.Fatalf("wrong kind %q", rec.got[0].Kind)
	}
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 1 {
		t.Fatalf("second check must not re-notify, got %d", rec.count())
	}
	if !strings.HasPrefix(*ua, "sanctum/") || strings.Contains(*ua, "@") {
		t.Fatalf("unexpected user agent %q", *ua)
	}
}

func TestSameOrOlderIsNotNewer(t *testing.T) {
	for _, cur := range []string{"0.2.0", "v0.2.0", "0.3.0", "1.0.0"} {
		srv, _ := serve(t, 200, rel)
		rec := &recorder{}
		info, err := newChecker(srv.URL, cur, rec).Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Newer || rec.count() != 0 {
			t.Fatalf("current %q: newer=%v notified=%d", cur, info.Newer, rec.count())
		}
	}
}

func TestDevBuildNeverClaimsAnUpdate(t *testing.T) {
	for _, cur := range []string{"dev", "", "0.0.0-dev", "garbage"} {
		srv, _ := serve(t, 200, rel)
		rec := &recorder{}
		info, err := newChecker(srv.URL, cur, rec).Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Newer || rec.count() != 0 {
			t.Fatalf("current %q must not report newer", cur)
		}
		if info.Latest != "v0.2.0" {
			t.Fatalf("latest should still be reported, got %q", info.Latest)
		}
	}
}

func TestBadResponsesAreErrors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"http 404":         {404, `{}`},
		"http 500":         {500, `oops`},
		"not json":         {200, `<html>`},
		"draft":            {200, `{"tag_name":"v9.9.9","draft":true}`},
		"prerelease":       {200, `{"tag_name":"v9.9.9","prerelease":true}`},
		"non-semver tag":   {200, `{"tag_name":"nightly"}`},
		"prerelease tag":   {200, `{"tag_name":"v1.0.0-rc1"}`},
		"two-part tag":     {200, `{"tag_name":"v1.0"}`},
		"huge number part": {200, `{"tag_name":"v1.0.99999999999"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _ := serve(t, tc.status, tc.body)
			rec := &recorder{}
			c := newChecker(srv.URL, "0.1.0", rec)
			if _, err := c.Check(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
			if rec.count() != 0 || c.Latest().Latest != "" {
				t.Fatal("a failed check must not notify or record a result")
			}
		})
	}
}

func TestRedirectIsRefused(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rel))
	}))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	t.Cleanup(srv.Close)
	if _, err := newChecker(srv.URL, "0.1.0", &recorder{}).Check(context.Background()); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}

func TestForeignReleaseURLIsDropped(t *testing.T) {
	srv, _ := serve(t, 200, `{"tag_name":"v0.2.0","html_url":"https://evil.example/x"}`)
	info, err := newChecker(srv.URL, "0.1.0", &recorder{}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.URL != "" {
		t.Fatalf("non-github URL must be dropped, got %q", info.URL)
	}
}

func TestNotifyFailureRetriesNextCheck(t *testing.T) {
	srv, _ := serve(t, 200, rel)
	rec := &recorder{fail: true}
	c := newChecker(srv.URL, "0.1.0", rec)
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 0 {
		t.Fatal("notify was failing")
	}
	rec.mu.Lock()
	rec.fail = false
	rec.mu.Unlock()
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 1 {
		t.Fatalf("a failed notification must be retried, got %d", rec.count())
	}
}

func TestUnreachableHostIsAnError(t *testing.T) {
	srv, _ := serve(t, 200, rel)
	url := srv.URL
	srv.Close()
	if _, err := newChecker(url, "0.1.0", &recorder{}).Check(context.Background()); err == nil {
		t.Fatal("expected an error for an unreachable host")
	}
}

func TestParseSemver(t *testing.T) {
	good := map[string]semver{"1.2.3": {1, 2, 3}, "v10.0.1": {10, 0, 1}, "v0.0.0": {0, 0, 0}}
	for in, want := range good {
		if got, ok := parseSemver(in); !ok || got != want {
			t.Fatalf("%q: got %v %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "v1", "1.2", "1.2.3.4", "1.2.x", "-1.0.0", "1.2.3-rc1", "dev", "v+1.+2.+3", "+1.2.3", "1.-2.3", "1. 2.3"} {
		if _, ok := parseSemver(in); ok {
			t.Fatalf("%q should be rejected", in)
		}
	}
}
