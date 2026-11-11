package httpapi

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		if strings.Count(strings.ToLower(s), "<script") > strings.Count(s, `<script src="/app.js" defer></script>`) {
			t.Errorf("%s has a script other than /app.js", p)
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
	if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'unsafe-inline") {
		t.Errorf("CSP must allow only our own script: %q", csp)
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

func TestThemeDefaultsToSystemAndCanBeChosen(t *testing.T) {
	e := newE2E(t)
	html := do(t, e, "GET", "/", nil, nil).Body.String()
	if strings.Contains(html, `<html lang="en" data-theme`) {
		t.Error("default must follow the system: no data-theme attribute")
	}
	rec := do(t, e, "POST", "/theme", url.Values{"theme": {"dark"}, "next": {"/status"}}, nil)
	if rec.Code != 303 || rec.Header().Get("Location") != "/status" {
		t.Fatalf("theme post: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == themeCookie {
			ck = c
		}
	}
	if ck == nil || ck.Value != "dark" {
		t.Fatalf("cookie not set: %+v", ck)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(ck)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `<html lang="en" data-theme="dark">`) {
		t.Error("saved dark theme not applied")
	}
	// An open redirect target is ignored.
	rec = do(t, e, "POST", "/theme", url.Values{"theme": {"auto"}, "next": {"https://evil.example"}}, nil)
	if rec.Header().Get("Location") != "/" {
		t.Errorf("redirect not pinned: %q", rec.Header().Get("Location"))
	}
}

func TestAppJSServedAndUploadFormHasProgress(t *testing.T) {
	e := newE2E(t)
	rec := do(t, e, "GET", "/app.js", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "XMLHttpRequest") {
		t.Fatalf("app.js: %d", rec.Code)
	}
	b, _ := fs.ReadFile(templatesFS, "templates/status.html")
	for _, want := range []string{"data-upload", `id="progbar"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status.html missing %s", want)
		}
	}
}

func TestLogoServedAndUsedInHeader(t *testing.T) {
	e := newE2E(t)
	for _, p := range []string{"/logo-96.png", "/logo-192.png"} {
		rec := do(t, e, "GET", p, nil, nil)
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || rec.Body.Len() < 1000 {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	html := do(t, e, "GET", "/", nil, nil).Body.String()
	if !strings.Contains(html, `src="/logo-96.png"`) {
		t.Error("header does not use the logo")
	}
	if csp := do(t, e, "GET", "/", nil, nil).Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self'") {
		t.Errorf("CSP blocks the logo: %q", csp)
	}
}
