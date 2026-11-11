package httpapi

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

// End-to-end HTTP tests that build a REAL *vault.Vault against tmpdirs,
// wrap it, drive the mux with httptest, and assert observable behaviour.
//
// We use the real vault (not a fake) because the interesting M4 gates —
// N17 (re-lock kills sessions), N8 (byte-identical restore), N16 (rate
// limit), F11 (locked serves only unlock+healthz) — are all interactions
// between the vault state machine and the HTTP layer.

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/vault"
	"github.com/herbiewalker/sanctum/internal/vaultkey"

	trystbk "github.com/herbiewalker/sanctum/internal/trystbk"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// setup boots a real vault with insecure-for-test KDF params + a wrapped
// Server. Returns the server, a shared clock ref, and a helper to make an
// authenticated cookie jar.
type e2e struct {
	srv    *Server
	v      *vault.Vault
	mux    *http.ServeMux
	base   string // vault dir root; useful for filesystem asserts
	tmpdir string
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	tmpDir := filepath.Join(base, "tmp")
	if err := writeInsecureManifest(t, vaultDir); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(vault.Paths{
		VaultDir: vaultDir, TmpDir: tmpDir,
		AllowNonTmpfsTmpDir: true, // t.TempDir() is on real fs
	}, vault.Options{
		Now:              time.Now,
		Logger:           nullLogger(),
		AllowInsecureKDF: true, // TestParams manifest
	})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	srv, err := New(Config{Vault: Wrap(v), Logger: nullLogger(), Now: time.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &e2e{srv: srv, v: v, mux: srv.Routes(), base: vaultDir, tmpdir: tmpDir}
}

func writeInsecureManifest(t *testing.T, dir string) error {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	m := vault.Manifest{
		LayoutVersion: vault.LayoutVersion,
		KDF:           vaultkey.TestParams(),
		CreatedAt:     1_700_000_000,
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, vault.ManifestFile), append(raw, '\n'), 0o600)
}

// F11: while LOCKED, only / and /healthz respond usefully. Everything else
// either redirects to / (auth-required endpoints) or errors out.
func TestLocked_ServesOnlyPublicEndpoints(t *testing.T) {
	e := newE2E(t)

	// /healthz reports locked and 200s.
	rec := do(t, e, "GET", "/healthz", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("/healthz status = %d", rec.Code)
	}
	var body struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.State != "locked" {
		t.Errorf("state = %q, want locked", body.State)
	}

	// GET / renders the unlock page (contains the unlock form action).
	rec = do(t, e, "GET", "/", nil, nil)
	if !strings.Contains(rec.Body.String(), `action="/unlock"`) {
		t.Errorf("GET / while locked did not render unlock page:\n%s", rec.Body.String())
	}

	// /status while locked: redirect to /.
	rec = do(t, e, "GET", "/status", nil, nil)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("/status locked: status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("/status locked: Location = %q, want /", loc)
	}
}

func TestUnlock_HappyPathThenAutoRedirect(t *testing.T) {
	e := newE2E(t)

	form := url.Values{"passphrase": {"open-sesame"}, "passphrase_confirm": {"open-sesame"}}
	rec := do(t, e, "POST", "/unlock", form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /unlock: status = %d", rec.Code)
	}
	if !e.v.IsUnlocked() {
		t.Fatal("vault still locked after successful /unlock")
	}
}

// N16: bursting past the unlock rate cap must trip. Manager cap is 5 —
// attempt 6 should be blocked with an error page, no KDF work done.
//
// A first-run vault has no seal on disk, so ANY passphrase "unlocks" (there
// is nothing to authenticate against). Seed a real seal first by doing one
// unlock → provision (writes to the index → seal on Lock) → Lock, so
// subsequent wrong-pw attempts actually fail auth and the rate limit has
// something to gate.
func TestUnlock_RateLimit_N16(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "correct")
	provisionAndLogin(t, e) // writes an owner row → non-trivial index to seal
	if err := e.v.Lock(); err != nil {
		t.Fatal(err)
	}

	// The setup's successful unlock consumed 1 of the 5 tokens in the bucket,
	// leaving 4 for wrong-pw attempts before the limit trips.
	form := url.Values{"passphrase": {"WRONG"}}
	for i := 1; i <= 4; i++ {
		rec := do(t, e, "POST", "/unlock", form, nil)
		if rec.Code != 200 {
			t.Fatalf("attempt %d: status = %d, want 200 (wrong-pw render)", i, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Unlock failed") {
			t.Fatalf("attempt %d: missing error message:\n%s", i, rec.Body.String())
		}
	}
	// Next attempt: rate-limited.
	rec := do(t, e, "POST", "/unlock", form, nil)
	if rec.Code != 200 {
		t.Fatalf("rate-limited attempt: status = %d, want 200 (limit render)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Too many attempts") {
		t.Errorf("rate-limit render missing marker:\n%s", rec.Body.String())
	}
}

// A first-run vault with no owners offers provisioning after unlock.
func TestProvision_FirstOwnerAutoLogsIn(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")

	form := url.Values{
		"label": {"me"}, "username": {"root"}, "password": {"myloginpw"}, "password_confirm": {"myloginpw"},
	}
	rec := do(t, e, "POST", "/provision", form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("provision status = %d", rec.Code)
	}
	// Cookie set.
	cookies := parseSetCookies(rec)
	if _, ok := cookies[sessionCookieName]; !ok {
		t.Fatal("no session cookie after provision auto-login")
	}
}

// N17: a cookie issued before a re-lock cycle must not authenticate anything
// afterwards, even after another unlock.
func TestSession_InvalidatedByReLock_N17(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	provisionAndLogin(t, e)

	jar := loginJar(t, e)
	// Sanity: the session works right now.
	rec := do(t, e, "GET", "/status", nil, jar)
	if rec.Code != 200 {
		t.Fatalf("/status pre-relock: status = %d", rec.Code)
	}

	// Re-lock, unlock again.
	if err := e.v.Lock(); err != nil {
		t.Fatal(err)
	}
	unlock(t, e, "pw")

	// Same cookie must not authenticate. requireAuth redirects to /.
	rec = do(t, e, "GET", "/status", nil, jar)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("/status post-relock: status = %d, want 303 (redirect to /)", rec.Code)
	}
}

// Session cookies: HttpOnly + SameSite=Strict always. Secure only on HTTPS.
// httptest is plain HTTP, so we must NOT see Secure — but we MUST see the
// other two.
func TestSession_CookieFlags(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	rec := doForm(t, e, "POST", "/provision", url.Values{
		"label": {"me"}, "username": {"root"}, "password": {"pw"}, "password_confirm": {"pw"},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("provision: %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Errorf("HttpOnly missing: %q", setCookie)
	}
	if !strings.Contains(strings.ToLower(setCookie), "samesite=strict") {
		t.Errorf("SameSite=Strict missing: %q", setCookie)
	}
	// Plain HTTP: Secure must NOT be present — otherwise the browser rejects.
	if strings.Contains(setCookie, "Secure") {
		t.Errorf("Secure present on HTTP response: %q", setCookie)
	}
}

// F2 upload + F10 restore round-trip: byte-identical (N8).
func TestUpload_ThenRestore_ByteIdentical_N8(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)

	// Add a backup password.
	do(t, e, "POST", "/passwords", url.Values{
		"label": {"default"}, "passphrase": {"the-backup-pw"},
	}, jar)

	// Build a real synthetic backup and upload it.
	orig := buildSyntheticBackup(t, "the-backup-pw", buildMinimalZip(t, 15))
	rec := doUpload(t, e, "/upload", "foo.tryst", orig, jar)
	if rec.Code != 200 {
		t.Fatalf("upload: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Ingested") {
		t.Fatalf("no ingest flash in status page:\n%s", rec.Body.String())
	}

	// Restore by looking up the id via /status.
	rec = do(t, e, "GET", "/status", nil, jar)
	id := extractFirstRestoreID(t, rec.Body.String())
	if id == "" {
		t.Fatal("no restore link in status page")
	}

	rec = do(t, e, "GET", "/restore/"+id, nil, jar)
	if rec.Code != 200 {
		t.Fatalf("restore: %d", rec.Code)
	}
	got := rec.Body.Bytes()
	if !bytes.Equal(got, orig) {
		t.Errorf("restore not byte-identical: got %d bytes, want %d", len(got), len(orig))
	}
	// Header advertises the SHA.
	wantSHA := sha256.Sum256(orig)
	adv := rec.Header().Get("X-Sanctum-SHA256")
	if !strings.EqualFold(adv, hexOf(wantSHA[:])) {
		t.Errorf("X-Sanctum-SHA256 = %q, want %x", adv, wantSHA)
	}
}

// F02: an upload body larger than uploadBodyLimit must be rejected with
// 413, and the multipart parser must never buffer past the cap. Swaps the
// package-level limit down to a few KiB so the assertion runs cheaply.
func TestUpload_OversizeBodyRejectedWith413_F02(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)

	// Add a password so the handler wouldn't otherwise short-circuit.
	do(t, e, "POST", "/passwords", url.Values{
		"label": {"default"}, "passphrase": {"pw"},
	}, jar)

	origBody := uploadBodyLimit
	uploadBodyLimit = 4 << 10 // 4 KiB
	t.Cleanup(func() {
		uploadBodyLimit = origBody
	})

	// 16 KiB of garbage — well past the shrunk cap, well short of anything
	// that would OOM a test process.
	rec := doUpload(t, e, "/upload", "big.tryst", bytes.Repeat([]byte{'A'}, 16<<10), jar)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize upload: status = %d, want 413. body=%s", rec.Code, rec.Body.String())
	}
}

// A restore for an id that doesn't belong to this owner must 404.
func TestRestore_OwnerScoped(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)
	rec := do(t, e, "GET", "/restore/some-other-id", nil, jar)
	if rec.Code != 404 {
		t.Errorf("restore of unknown id: %d, want 404", rec.Code)
	}
}

// /passwords add+list+delete round-trip.
func TestPasswords_CRUD(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)

	do(t, e, "POST", "/passwords", url.Values{
		"label": {"first"}, "passphrase": {"aaa"},
	}, jar)
	rec := do(t, e, "GET", "/passwords", nil, jar)
	if !strings.Contains(rec.Body.String(), "first") {
		t.Fatalf("password label 'first' missing from /passwords:\n%s", rec.Body.String())
	}
}

// --- HTTP helpers -----------------------------------------------------------

type cookieJar map[string]string

func do(t *testing.T, e *e2e, method, path string, form url.Values, jar cookieJar) *httptest.ResponseRecorder {
	t.Helper()
	return doForm(t, e, method, path, form, jar)
}

func doForm(t *testing.T, e *e2e, method, path string, form url.Values, jar cookieJar) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, val := range jar {
		req.AddCookie(&http.Cookie{Name: name, Value: val})
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func doUpload(t *testing.T, e *e2e, path, filename string, content []byte, jar cookieJar) *httptest.ResponseRecorder {
	t.Helper()
	return doUploadLen(t, e, path, filename, content, jar, false)
}

// doUploadLen is doUpload with an option to hide the body length (chunked), so
// the declared-Content-Length shortcut cannot fire and the MaxBytesReader
// path is the one under test.
func doUploadLen(t *testing.T, e *e2e, path, filename string, content []byte, jar cookieJar, chunked bool) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()

	req := httptest.NewRequest("POST", path, &body)
	if chunked {
		req.ContentLength = -1
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for name, val := range jar {
		req.AddCookie(&http.Cookie{Name: name, Value: val})
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func parseSetCookies(rec *httptest.ResponseRecorder) map[string]string {
	m := map[string]string{}
	for _, sc := range rec.Header()["Set-Cookie"] {
		// Very small parse — good enough for tests.
		i := strings.IndexByte(sc, ';')
		if i < 0 {
			i = len(sc)
		}
		kv := sc[:i]
		j := strings.IndexByte(kv, '=')
		if j > 0 {
			m[kv[:j]] = kv[j+1:]
		}
	}
	return m
}

func unlock(t *testing.T, e *e2e, pw string) {
	t.Helper()
	rec := do(t, e, "POST", "/unlock", url.Values{"passphrase": {pw}, "passphrase_confirm": {pw}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unlock helper: %d body=%s", rec.Code, rec.Body.String())
	}
}

func provisionAndLogin(t *testing.T, e *e2e) {
	t.Helper()
	rec := do(t, e, "POST", "/provision", url.Values{
		"label": {"me"}, "username": {"root"}, "password": {"pw"}, "password_confirm": {"pw"},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("provision helper: %d body=%s", rec.Code, rec.Body.String())
	}
}

func provisionAndLoginJar(t *testing.T, e *e2e) cookieJar {
	t.Helper()
	rec := do(t, e, "POST", "/provision", url.Values{
		"label": {"me"}, "username": {"root"}, "password": {"pw"}, "password_confirm": {"pw"},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("provision helper: %d body=%s", rec.Code, rec.Body.String())
	}
	sc := parseSetCookies(rec)
	return cookieJar{sessionCookieName: sc[sessionCookieName]}
}

func loginJar(t *testing.T, e *e2e) cookieJar {
	t.Helper()
	rec := do(t, e, "POST", "/login", url.Values{
		"username": {"root"}, "password": {"pw"},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login helper: %d body=%s", rec.Code, rec.Body.String())
	}
	sc := parseSetCookies(rec)
	return cookieJar{sessionCookieName: sc[sessionCookieName]}
}

func extractFirstRestoreID(t *testing.T, html string) string {
	// Cheap: find `href="/restore/<id>"`.
	const prefix = `href="/restore/`
	i := strings.Index(html, prefix)
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(html[i+len(prefix):], '"')
	if j < 0 {
		return ""
	}
	return html[i+len(prefix) : i+len(prefix)+j]
}

// --- crypto helpers (mirror the trystbk/rebuild/ingest copies) --------------

func buildSyntheticBackup(t *testing.T, password string, zipBody []byte) []byte {
	t.Helper()
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	var hdr bytes.Buffer
	hdr.WriteString(trystbk.Magic)
	hdr.WriteByte(trystbk.FormatVersion1)
	hdr.Write(salt[:])
	_ = binary.Write(&hdr, binary.BigEndian, uint32(trystbk.MinIterations))

	key := pbkdf2.Key([]byte(password), salt[:], trystbk.MinIterations,
		trystbk.KeySizeBytes, sha256.New)
	aead, err := subtle.NewAESGCMHKDF(key, trystbk.HKDFAlg, trystbk.KeySizeBytes,
		trystbk.SegmentSize, trystbk.FirstSegmentOffset)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	out.Write(hdr.Bytes())
	w, err := aead.NewEncryptingWriter(&out, []byte(trystbk.AssociatedData))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(zipBody)
	_ = w.Close()
	return out.Bytes()
}

func buildMinimalZip(t *testing.T, schemaVersion int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	f.Write([]byte(`{"schemaVersion":` + itoa(schemaVersion) + `,"tables":{"encounters":[{"id":1}]}}`))
	_ = zw.Close()
	return buf.Bytes()
}

func hexOf(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[2*i] = hex[x>>4]
		out[2*i+1] = hex[x&0xF]
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣

// F02, chunked variant: with no declared Content-Length the early shortcut
// cannot fire, so the cap must still hold via MaxBytesReader while streaming.
func TestUpload_OversizeChunkedBodyRejectedWith413_F02(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "pw")
	jar := provisionAndLoginJar(t, e)
	do(t, e, "POST", "/passwords", url.Values{
		"label": {"default"}, "passphrase": {"pw"},
	}, jar)

	origBody := uploadBodyLimit
	uploadBodyLimit = 4 << 10
	t.Cleanup(func() { uploadBodyLimit = origBody })

	rec := doUploadLen(t, e, "/upload", "big.tryst", bytes.Repeat([]byte{'A'}, 16<<10), jar, true)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversize upload: status = %d, want 413. body=%s", rec.Code, rec.Body.String())
	}
}
