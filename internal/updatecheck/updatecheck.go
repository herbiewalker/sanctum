// Package updatecheck asks GitHub whether a newer Sanctum release exists and
// reports it. That is ALL it does (ADR D-19): it never downloads, never runs,
// and never touches Docker. Applying an update is the operator's act, done the
// normal Docker way (pull the new image, restart, unlock).
//
// Privacy: the only thing sent is a GET to the public releases API with a
// `sanctum/<version>` User-Agent. GitHub sees the host's IP; nothing about the
// vault, its owners, or its contents is ever in the request or the logs (N15).
// The whole feature is opt-in (SANCTUM_UPDATE_CHECK) and off when unset.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/herbiewalker/sanctum/internal/notify"
)

// DefaultAPIURL is the public, unauthenticated "latest release" endpoint. It
// excludes drafts and prereleases by definition.
const DefaultAPIURL = "https://api.github.com/repos/herbiewalker/sanctum/releases/latest"

// maxResponseBytes bounds what we read back; a release JSON is a few KB.
const maxResponseBytes = 1 << 20

// Info is the result of the most recent successful check.
type Info struct {
	Latest    string    // e.g. "v0.2.0"; empty until a check has succeeded
	URL       string    // the release page
	Newer     bool      // Latest is strictly newer than the running version
	CheckedAt time.Time // when the check last succeeded
}

// Options configures a Checker. Zero values get safe defaults.
type Options struct {
	Current  string // running version, e.g. "0.1.0", "v0.1.0" or "dev"
	APIURL   string // default DefaultAPIURL; overridden in tests
	Client   *http.Client
	Notifier notify.Notifier
	Now      func() time.Time
	Logger   *slog.Logger
}

// Checker polls the releases API. Safe for concurrent use.
type Checker struct {
	opt Options

	mu       sync.Mutex
	info     Info
	notified string // latest tag we already raised a notification for
}

// New builds a Checker.
func New(o Options) *Checker {
	if o.APIURL == "" {
		o.APIURL = DefaultAPIURL
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: 10 * time.Second,
			// A renamed repo answers with a redirect; refusing it keeps the
			// request pinned to the one host we configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if o.Notifier == nil {
		o.Notifier = notify.NullNotifier{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Checker{opt: o}
}

// Latest returns the last successful result (zero Info before the first one).
func (c *Checker) Latest() Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

type release struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Check performs one lookup, updates Latest(), and raises a single
// notification the first time a given newer version is seen.
func (c *Checker) Check(ctx context.Context) (Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.opt.APIURL, nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sanctum/"+displayVersion(c.opt.Current))

	resp, err := c.opt.Client.Do(req)
	if err != nil {
		return Info{}, fmt.Errorf("updatecheck: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("updatecheck: unexpected status %d", resp.StatusCode)
	}

	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&rel); err != nil {
		return Info{}, fmt.Errorf("updatecheck: decode: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return Info{}, errors.New("updatecheck: latest release is a draft or prerelease; ignoring")
	}
	latest, ok := parseSemver(rel.TagName)
	if !ok {
		return Info{}, fmt.Errorf("updatecheck: unrecognised tag %q", truncate(rel.TagName, 40))
	}

	info := Info{
		Latest:    rel.TagName,
		URL:       safeReleaseURL(rel.HTMLURL),
		CheckedAt: c.opt.Now(),
	}
	if cur, ok := parseSemver(c.opt.Current); ok {
		info.Newer = cur.less(latest)
	}

	c.mu.Lock()
	c.info = info
	alreadyNotified := c.notified == info.Latest
	c.mu.Unlock()

	if info.Newer && !alreadyNotified {
		body := fmt.Sprintf("Sanctum %s is available (running %s). Pull the new image and restart; "+
			"the vault will be locked afterwards and needs unlocking.",
			info.Latest, displayVersion(c.opt.Current))
		if err := c.opt.Notifier.Notify(notify.Intent{
			At:       c.opt.Now().Unix(),
			Severity: notify.SeverityNormal,
			Kind:     notify.KindUpdate,
			Subject:  "update available",
			Body:     body,
		}); err != nil {
			// Not marked as notified, so the next check retries.
			c.opt.Logger.Warn("update notification failed", "err", err.Error())
		} else {
			c.mu.Lock()
			c.notified = info.Latest
			c.mu.Unlock()
		}
	}
	return info, nil
}

// Run checks once shortly after start, then every `every` until ctx ends.
// Failures are logged at warn level and never affect the rest of the service.
func (c *Checker) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	timer := time.NewTimer(30 * time.Second) // let the service settle first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if info, err := c.Check(ctx); err != nil {
				c.opt.Logger.Warn("update check failed", "err", err.Error())
			} else {
				c.opt.Logger.Info("update check", "latest", info.Latest, "newer", info.Newer)
			}
			timer.Reset(every)
		}
	}
}

// safeReleaseURL only passes through https links to github.com so a hostile
// API response cannot plant an arbitrary link in the UI.
func safeReleaseURL(u string) string {
	if strings.HasPrefix(u, "https://github.com/") {
		return u
	}
	return ""
}

func displayVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type semver struct{ major, minor, patch int }

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// parseSemver accepts "1.2.3" or "v1.2.3" only. Anything else (a "dev" build,
// a prerelease suffix, a bare "v1") is rejected, so a dev build never claims
// an update is "newer".
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var n [3]int
	for i, p := range parts {
		if p == "" || len(p) > 6 {
			return semver{}, false
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return semver{}, false
		}
		n[i] = v
	}
	return semver{n[0], n[1], n[2]}, true
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
