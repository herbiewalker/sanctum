package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// URL channels (ADR D-20). One configured URL delivers every intent straight
// from the container to a messaging service, so a user pastes one setting and
// needs no host-side script. Supported forms:
//
//	ntfy://[user:pass@|:token@]host[:port]/topic      ntfy over https
//	ntfy+http://host[:port]/topic                      ntfy over plain http (LAN)
//	https://discord.com/api/webhooks/...               Discord webhook
//	https://hooks.slack.com/services/...               Slack webhook
//	https://... or http://...                          generic webhook (POST JSON)
//
// The URL is a credential (the token lives in its path or userinfo). It is
// never logged and never put in an error: Describe() reports only the kind and
// host, and every error here is written without the URL.

const (
	urlTimeout       = 10 * time.Second
	maxDrainBytes    = 64 << 10
	maxURLsPerConfig = 4
)

// URLNotifier posts intents to one HTTP endpoint.
type URLNotifier struct {
	kind   string // "ntfy", "discord", "slack", "webhook"
	target string // the URL actually POSTed to (secret)
	host   string // safe to log
	user   string // ntfy basic-auth user (secret)
	pass   string // ntfy basic-auth password or bearer token (secret)
	client *http.Client
}

// ParseURL builds a notifier from one URL. The error never contains the URL.
func ParseURL(raw string) (*URLNotifier, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("notify: notification URL is not a valid URL")
	}
	n := &URLNotifier{host: u.Host, client: &http.Client{
		Timeout: urlTimeout,
		// A redirect could carry the token to a different host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}

	switch u.Scheme {
	case "ntfy", "ntfy+http":
		if strings.Trim(u.Path, "/") == "" {
			return nil, errors.New("notify: ntfy URL needs a topic, e.g. ntfy://host/topic")
		}
		n.kind = "ntfy"
		scheme := "https"
		if u.Scheme == "ntfy+http" {
			scheme = "http"
		}
		if u.User != nil {
			n.user = u.User.Username()
			n.pass, _ = u.User.Password()
		}
		t := url.URL{Scheme: scheme, Host: u.Host, Path: u.Path}
		n.target = t.String()
	case "https", "http":
		n.target = u.String()
		switch {
		case (u.Hostname() == "discord.com" || u.Hostname() == "discordapp.com") &&
			strings.HasPrefix(u.Path, "/api/webhooks/"):
			n.kind = "discord"
		case u.Hostname() == "hooks.slack.com":
			n.kind = "slack"
		default:
			n.kind = "webhook"
		}
	default:
		return nil, errors.New("notify: notification URL scheme must be ntfy, ntfy+http, https or http")
	}
	return n, nil
}

// Describe is safe to log: channel kind and host only, never the path or
// credentials.
func (n *URLNotifier) Describe() string { return n.kind + "@" + n.host }

// Notify delivers one intent. It returns an error unless the endpoint answers
// 2xx.
func (n *URLNotifier) Notify(in Intent) error {
	if err := validate(in); err != nil {
		return err
	}
	req, err := n.request(in)
	if err != nil {
		return err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		// err can embed the URL; report the channel only.
		return fmt.Errorf("notify: %s delivery failed (network error)", n.Describe())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: %s answered HTTP %d", n.Describe(), resp.StatusCode)
	}
	return nil
}

func (n *URLNotifier) request(in Intent) (*http.Request, error) {
	var (
		body []byte
		ct   string
		err  error
	)
	switch n.kind {
	case "ntfy":
		body, ct = []byte(in.Body), "text/plain; charset=utf-8"
	case "discord":
		// D10: allowed_mentions with an empty parse list stops an owner label such as
		// "@everyone" from pinging the whole channel.
		body, err = json.Marshal(map[string]any{
			"content":          truncate("**"+in.Subject+"**\n"+in.Body, 1900),
			"allowed_mentions": map[string][]string{"parse": {}},
		})
		ct = "application/json"
	case "slack":
		body, err = json.Marshal(map[string]string{"text": truncate("*"+in.Subject+"*\n"+in.Body, 3000)})
		ct = "application/json"
	default:
		out := in
		out.Schema = SchemaVersion
		body, err = json.Marshal(out)
		ct = "application/json"
	}
	if err != nil {
		return nil, errors.New("notify: encode failed")
	}
	req, err := http.NewRequest(http.MethodPost, n.target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("notify: build request failed")
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("User-Agent", "sanctum-notify")
	if n.kind == "ntfy" {
		req.Header.Set("Title", headerSafe(in.Subject))
		req.Header.Set("Priority", ntfyPriority(in.Severity))
		req.Header.Set("Tags", ntfyTag(in.Severity))
		switch {
		case n.user != "":
			req.SetBasicAuth(n.user, n.pass)
		case n.pass != "":
			req.Header.Set("Authorization", "Bearer "+n.pass)
		}
	}
	return req, nil
}

func ntfyPriority(s Severity) string {
	switch s {
	case SeverityAlert:
		return "5"
	case SeverityWarning:
		return "4"
	}
	return "3"
}

func ntfyTag(s Severity) string {
	switch s {
	case SeverityAlert:
		return "rotating_light"
	case SeverityWarning:
		return "warning"
	}
	return "information_source"
}

// headerSafe strips control characters so a subject can never inject a header.
func headerSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && r < 0x80 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// D10: cut on a rune boundary so a multi-byte character is never split.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ParseURLs parses a comma-separated list (at most maxURLsPerConfig).
func ParseURLs(list string) ([]*URLNotifier, error) {
	var out []*URLNotifier
	for _, part := range strings.Split(list, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		n, err := ParseURL(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if len(out) > maxURLsPerConfig {
		return nil, fmt.Errorf("notify: at most %d notification URLs are supported", maxURLsPerConfig)
	}
	return out, nil
}

// Multi fans an intent out to several channels. It succeeds if at least one
// channel delivered, so a dead webhook cannot suppress the drop-folder copy
// (or the reverse); it fails only when every channel failed.
type Multi struct{ Channels []Notifier }

func (m Multi) Notify(in Intent) error {
	if len(m.Channels) == 0 {
		return nil
	}
	var errs []error
	ok := false
	for _, c := range m.Channels {
		if err := c.Notify(in); err != nil {
			errs = append(errs, err)
			continue
		}
		ok = true
	}
	if ok {
		return nil
	}
	return errors.Join(errs...)
}
