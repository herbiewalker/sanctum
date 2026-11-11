package httpapi

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The UI is plain HTML and CSS: no script, no inline event handlers, and no
// resource fetched from another host. That keeps it working offline on a LAN,
// in any browser, and lets the Content-Security-Policy stay strict.
func TestUITemplatesAreScriptFreeAndSelfContained(t *testing.T) {
	ext := regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*"https?://`)
	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	err := fs.WalkDir(templatesFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := fs.ReadFile(templatesFS, p)
		if rerr != nil {
			return rerr
		}
		s := string(b)
		if strings.Contains(strings.ToLower(s), "<script") {
			t.Errorf("%s contains <script>", p)
		}
		if handler.MatchString(s) {
			t.Errorf("%s has an inline event handler", p)
		}
		if ext.MatchString(s) {
			t.Errorf("%s loads a resource from another host", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUISendsStrictCSP(t *testing.T) {
	e := newE2E(t)
	rec := do(t, e, "GET", "/", nil, nil)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'self'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q is missing %q", csp, want)
		}
	}
	if strings.Contains(csp, "script-src") || strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP must not allow scripts: %q", csp)
	}
}

// Every page declares a responsive viewport and a skip link, so it works at any
// width and with a keyboard.
func TestUILayoutIsResponsiveAndAccessible(t *testing.T) {
	e := newE2E(t)
	html := do(t, e, "GET", "/", nil, nil).Body.String()
	for _, want := range []string{`name="viewport"`, `width=device-width`, `class="skip"`, `lang="en"`, `prefers-color-scheme: dark`} {
		if !strings.Contains(html, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}
