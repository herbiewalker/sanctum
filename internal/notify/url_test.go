package notify

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type captured struct {
	method string
	path   string
	header http.Header
	body   string
}

func capture(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.method, c.path, c.header, c.body = r.Method, r.URL.Path, r.Header.Clone(), string(b)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

var sample = Intent{Severity: SeverityAlert, Kind: KindLockedSince,
	Subject: "Sanctum: vault has been locked", Body: "Locked since X (5 minutes)."}

func TestNtfyDelivery(t *testing.T) {
	srv, c := capture(t, 200)
	n, err := ParseURL("ntfy+http://" + strings.TrimPrefix(srv.URL, "http://") + "/my-topic")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(sample); err != nil {
		t.Fatal(err)
	}
	if c.method != "POST" || c.path != "/my-topic" || c.body != sample.Body {
		t.Fatalf("unexpected request %+v", c)
	}
	if c.header.Get("Title") != sample.Subject || c.header.Get("Priority") != "5" ||
		c.header.Get("Tags") != "rotating_light" {
		t.Fatalf("bad ntfy headers %v", c.header)
	}
}

func TestNtfyAuth(t *testing.T) {
	srv, c := capture(t, 200)
	host := strings.TrimPrefix(srv.URL, "http://")

	n, _ := ParseURL("ntfy+http://:tk_secret@" + host + "/t")
	if err := n.Notify(sample); err != nil {
		t.Fatal(err)
	}
	if c.header.Get("Authorization") != "Bearer tk_secret" {
		t.Fatalf("token-only must be a bearer, got %q", c.header.Get("Authorization"))
	}

	n, _ = ParseURL("ntfy+http://bob:pw@" + host + "/t")
	if err := n.Notify(sample); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.header.Get("Authorization"), "Basic ") {
		t.Fatalf("user:pass must be basic auth, got %q", c.header.Get("Authorization"))
	}
}

func TestHeaderInjectionIsStripped(t *testing.T) {
	srv, c := capture(t, 200)
	n, _ := ParseURL("ntfy+http://" + strings.TrimPrefix(srv.URL, "http://") + "/t")
	in := sample
	in.Subject = "ok\r\nX-Evil: 1"
	if err := n.Notify(in); err != nil {
		t.Fatal(err)
	}
	if c.header.Get("X-Evil") != "" {
		t.Fatal("a subject must not be able to inject a header")
	}
}

func TestGenericWebhookPostsJSON(t *testing.T) {
	srv, c := capture(t, 204)
	n, err := ParseURL(srv.URL + "/hook/abc")
	if err != nil {
		t.Fatal(err)
	}
	if n.kind != "webhook" {
		t.Fatalf("kind %q", n.kind)
	}
	if err := n.Notify(sample); err != nil {
		t.Fatal(err)
	}
	var got Intent
	if err := json.Unmarshal([]byte(c.body), &got); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if got.Subject != sample.Subject || got.Kind != KindLockedSince || got.Schema != SchemaVersion {
		t.Fatalf("unexpected payload %+v", got)
	}
}

func TestDiscordAndSlackShapes(t *testing.T) {
	cases := []struct {
		raw  string
		kind string
		key  string
	}{
		{"https://discord.com/api/webhooks/1/abc", "discord", "content"},
		{"https://hooks.slack.com/services/T/B/x", "slack", "text"},
	}
	for _, tc := range cases {
		n, err := ParseURL(tc.raw)
		if err != nil || n.kind != tc.kind {
			t.Fatalf("%s: kind %q err %v", tc.raw, n.kind, err)
		}
		req, err := n.request(sample)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(req.Body)
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil || !strings.Contains(m[tc.key], sample.Subject) {
			t.Fatalf("%s: bad body %s (%v)", tc.kind, b, err)
		}
	}
}

func TestNon2xxAndRedirectAreErrors(t *testing.T) {
	srv, _ := capture(t, 500)
	n, _ := ParseURL(srv.URL + "/secret-token-path")
	err := n.Notify(sample)
	if err == nil {
		t.Fatal("HTTP 500 must be an error")
	}

	target, _ := capture(t, 200)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	n, _ = ParseURL(redir.URL + "/secret-token-path")
	if err := n.Notify(sample); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}

func TestErrorsNeverContainTheSecret(t *testing.T) {
	// Unreachable host: the Go error would normally embed the full URL.
	srv, _ := capture(t, 200)
	dead := srv.URL
	srv.Close()
	n, _ := ParseURL(dead + "/hook/SUPERSECRETTOKEN")
	err := n.Notify(sample)
	if err == nil {
		t.Fatal("expected a network error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETTOKEN") {
		t.Fatalf("error leaks the URL: %v", err)
	}
	if strings.Contains(n.Describe(), "SUPERSECRETTOKEN") {
		t.Fatal("Describe leaks the URL")
	}

	_, err = ParseURL("ftp://x/SUPERSECRETTOKEN")
	if err == nil || strings.Contains(err.Error(), "SUPERSECRETTOKEN") {
		t.Fatalf("parse error must not echo the URL: %v", err)
	}
}

func TestParseRejections(t *testing.T) {
	for _, raw := range []string{"", "not a url", "ftp://host/x", "ntfy://host", "ntfy://host/", "https://"} {
		if _, err := ParseURL(raw); err == nil {
			t.Fatalf("%q should be rejected", raw)
		}
	}
	if _, err := ParseURLs("https://a.example/1,https://b.example/2,https://c.example/3,https://d.example/4,https://e.example/5"); err == nil {
		t.Fatal("more than 4 URLs must be rejected")
	}
	ns, err := ParseURLs(" https://a.example/1 , ,ntfy://n.example/t ")
	if err != nil || len(ns) != 2 {
		t.Fatalf("got %d, %v", len(ns), err)
	}
}

type stub struct {
	err   error
	calls int
}

func (s *stub) Notify(Intent) error { s.calls++; return s.err }

func TestMultiSucceedsIfAnyChannelDelivers(t *testing.T) {
	good, bad := &stub{}, &stub{err: errors.New("down")}
	if err := (Multi{Channels: []Notifier{bad, good}}).Notify(sample); err != nil {
		t.Fatalf("one working channel must be enough: %v", err)
	}
	if good.calls != 1 || bad.calls != 1 {
		t.Fatal("every channel must be tried")
	}
	if err := (Multi{Channels: []Notifier{bad, bad}}).Notify(sample); err == nil {
		t.Fatal("all channels failing must be an error")
	}
	if err := (Multi{}).Notify(sample); err != nil {
		t.Fatal("no channels is not an error")
	}
}

func TestUpdateKindIsAccepted(t *testing.T) {
	in := Intent{Severity: SeverityNormal, Kind: KindUpdate, Subject: "update available"}
	if err := validate(in); err != nil {
		t.Fatalf("the update check raises this kind: %v", err)
	}
}
