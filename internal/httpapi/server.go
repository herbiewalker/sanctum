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
// Package httpapi is Sanctum's HTTP surface.
//
// The routes and their gating (LOCKED / UNLOCKED-but-anonymous / authenticated)
// are laid out in Routes(). The whole surface is intentionally small and
// single-purpose — one HTML page per view, form posts, no JS. That keeps the
// audit surface for M4 audit passes tight (Phase 3) and matches the
// docker-service adapter's principle of minimal exposure.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/ingest"
	"github.com/herbiewalker/sanctum/internal/session"
	"github.com/herbiewalker/sanctum/internal/trystbk"
	"github.com/herbiewalker/sanctum/internal/vault"
)

// uploadBodyLimit caps the total upload body size for /upload. A well-formed
// TRYSTBK1 is at most MaxBackupBytes; the extra slack covers the multipart
// framing (boundary lines, part headers) around it. Declared as var (not
// const) so tests can shrink it and exercise the 413 path without moving
// 512 MiB through httptest.
//
// The upload is NOT run through ParseMultipartForm any more: that spilled the
// whole body to a temp file on the tmpfs (up to the cap) before the size
// check could fire, and ingest then staged a second copy, so a hostile or
// merely oversize upload cost ~2x its size in tmpfs (found by the live smoke
// test, 2026-11-09). handleUpload streams the file part straight into ingest's
// single staging copy, and rejects on a declared Content-Length before
// reading anything.
var uploadBodyLimit = int64(trystbk.MaxBackupBytes) + (64 << 10)

//go:embed templates/*.html
var templatesFS embed.FS

// Cookie name for the owner-login session (D-14).
const sessionCookieName = "sanctum_session"

// Server holds handler dependencies. One instance per running process.
type Server struct {
	vault  Vault // real *vault.Vault via Wrap(), or a test double
	logger *slog.Logger
	tmpl   *template.Template

	unlockLimit *limiter
	loginLimit  *limiter

	now func() time.Time

	version    string
	updateInfo func() UpdateInfo

	lockedSince   func() int64 // unix seconds the vault was locked; 0 = unknown
	stalenessDays int          // global stale threshold for the UI warning; 0 = off
}

// UpdateInfo is what the UI needs to show an "update available" banner. It
// carries only public release metadata, never anything about the vault.
type UpdateInfo struct {
	Newer  bool
	Latest string
	URL    string
}

// Vault is the surface httpapi needs. Kept as an interface so tests can
// substitute without spinning up a real *vault.Vault (though the e2e test
// does use the real one). Blob open for restore lives on a separate
// BlobOpener interface — see adapter.go — so this stays small.
type Vault interface {
	IsUnlocked() bool
	Unlock(passphrase string) error
	Lock() error
	Index() *index.Index
	Ingest() *ingest.Service
	Sessions() *session.Manager
}

// realVault adapts *vault.Vault to the httpapi.Vault interface and
// (via adapter.go) BlobOpener.
type realVault struct{ v *vault.Vault }

// Wrap returns a *vault.Vault as a httpapi.Vault + BlobOpener.
func Wrap(v *vault.Vault) Vault { return &realVault{v: v} }

func (r *realVault) IsUnlocked() bool           { return r.v.IsUnlocked() }
func (r *realVault) Unlock(p string) error      { return r.v.Unlock(p) }
func (r *realVault) Lock() error                { return r.v.Lock() }
func (r *realVault) Index() *index.Index        { return r.v.Index() }
func (r *realVault) Ingest() *ingest.Service    { return r.v.Ingest() }
func (r *realVault) Sessions() *session.Manager { return r.v.Sessions() }
func (r *realVault) FirstRun() bool             { return r.v.FirstRun() }

// Config wires the server.
type Config struct {
	Vault  Vault
	Logger *slog.Logger
	Now    func() time.Time

	// Version is the running build, shown in the footer once logged in.
	Version string
	// UpdateInfo, if set, feeds the "update available" banner. Optional.
	UpdateInfo func() UpdateInfo
	// LockedSince reports when the vault was locked (unix seconds, 0 unknown)
	// so the unlock page can say how long ingest has been paused. Optional.
	LockedSince func() int64
	// StalenessDays is the global threshold behind the "backup is stale"
	// warning on the status page. 0 disables the warning.
	StalenessDays int
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Vault == nil {
		return nil, errors.New("httpapi: nil vault")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("httpapi: parse templates: %w", err)
	}
	return &Server{
		vault:         cfg.Vault,
		logger:        cfg.Logger,
		tmpl:          tmpl,
		unlockLimit:   newLimiter(unlockRate, cfg.Now),
		loginLimit:    newLimiter(loginRate, cfg.Now),
		now:           cfg.Now,
		version:       cfg.Version,
		updateInfo:    cfg.UpdateInfo,
		lockedSince:   cfg.LockedSince,
		stalenessDays: cfg.StalenessDays,
	}, nil
}

// Routes returns the mux. Kept as a single method so an audit read of the
// exposed surface is one screen.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Always-available.
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// The landing page: chooses unlock vs login vs dashboard.
	mux.HandleFunc("GET /", s.handleRoot)

	// Vault-lock control.
	mux.HandleFunc("POST /unlock", s.handleUnlock)
	mux.HandleFunc("POST /lock", s.handleLock)

	// Owner auth.
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /provision", s.handleProvision)

	// Authenticated actions.
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("POST /upload", s.handleUpload)
	mux.HandleFunc("GET /restore/{id}", s.handleRestore)
	mux.HandleFunc("GET /passwords", s.handlePasswords)
	mux.HandleFunc("POST /passwords", s.handlePasswordAdd)
	mux.HandleFunc("POST /passwords/{id}/delete", s.handlePasswordDelete)

	return mux
}

// --- shared render helpers --------------------------------------------------

// viewData is what every template gets. Fields are populated by the handler
// before render; nils/zero-values behave sanely in the template. `Body` is
// the name of the {{define "body_*"}} block to dispatch into — a discrete
// name per page avoids the html/template "last-defined content wins"
// footgun when every page defines the same block name.
type viewData struct {
	Body           string // e.g. "body_unlock", "body_status"
	Unlocked       bool
	Authed         bool
	NeedsProvision bool
	// FirstRun is true on a vault that has never been locked: whatever is typed
	// at unlock becomes the passphrase, so the page asks for it twice.
	FirstRun  bool
	Flash     string
	Error     string
	Status    *statusView
	Passwords []passwordRow

	// Set by render() for logged-in pages only, so the version of a locked or
	// not-yet-authenticated instance is not handed to everyone on the LAN.
	Version string
	Update  *UpdateInfo

	// Warn is a plain-language warning shown above the page (vault locked for
	// a long time, backup is stale). Contains no secret material.
	Warn string
}

// bodyFor maps a "page name" to its dispatched block. Kept centralised so
// the render() sites just pass a symbolic name; the layout uses the value
// via `{{template .Body .}}`.
var bodyFor = map[string]string{
	"unlock.html":    "body_unlock",
	"login.html":     "body_login",
	"status.html":    "body_status",
	"passwords.html": "body_passwords",
}

func (s *Server) render(w http.ResponseWriter, name string, data viewData) {
	data.Body = bodyFor[name]
	if name == "unlock.html" {
		data.FirstRun = s.firstRun()
	}
	if data.Warn == "" {
		data.Warn = s.warning(data)
	}
	if data.Authed {
		data.Version = s.version
		if s.updateInfo != nil {
			if u := s.updateInfo(); u.Newer {
				data.Update = &u
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("template render", "page", name, "err", err.Error())
	}
}

// --- always-available -------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Status string `json:"status"`
		State  string `json:"state"`
	}{Status: "ok"}
	if s.vault.IsUnlocked() {
		body.State = "unlocked"
	} else {
		body.State = "locked"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// handleRoot picks the right view based on state.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !s.vault.IsUnlocked() {
		s.render(w, "unlock.html", viewData{Unlocked: false})
		return
	}
	sess, _ := s.currentSession(r)
	if sess == nil {
		// Unlocked but not logged in. Show the login form; if no owners
		// exist yet, offer the first-run provisioning form instead.
		needsProv, _ := s.noOwnersYet()
		s.render(w, "login.html", viewData{Unlocked: true, NeedsProvision: needsProv})
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

// --- vault lock/unlock ------------------------------------------------------

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.unlockLimit.Allow(clientIP(r)) {
		s.logger.Warn("unlock rate-limited", "ip", clientIP(r))
		s.render(w, "unlock.html", viewData{
			Unlocked: false,
			Error:    "Too many attempts. Wait a minute before trying again.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pw := r.PostForm.Get("passphrase")
	if pw == "" {
		s.render(w, "unlock.html", viewData{Unlocked: false, Error: "Passphrase required."})
		return
	}
	// Brand-new vault: this passphrase will become the one that protects
	// everything, so make the operator type it twice. A mismatch creates nothing.
	if s.firstRun() && r.PostForm.Get("passphrase_confirm") != pw {
		s.render(w, "unlock.html", viewData{
			Unlocked: false,
			Error:    "The two passphrases do not match. Nothing was created; try again.",
		})
		return
	}
	if err := s.vault.Unlock(pw); err != nil {
		s.logger.Warn("vault unlock failed", "ip", clientIP(r), "err", err.Error())
		s.render(w, "unlock.html", viewData{
			Unlocked: false,
			Error:    "Unlock failed — wrong passphrase, or the seal is corrupted.",
		})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	// Anyone with a valid session can lock. This is deliberate: an authed
	// caller who wants to end their session by locking the whole vault is a
	// legitimate operator action.
	if _, err := s.requireAuth(w, r); err != nil {
		return
	}
	if err := s.vault.Lock(); err != nil {
		s.logger.Error("vault lock failed", "err", err.Error())
	}
	// Session cookies are invalidated by vault.Lock (N17); the browser's
	// cookie is now useless.
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- owner auth -------------------------------------------------------------

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	if !s.vault.IsUnlocked() {
		http.Error(w, "vault locked", http.StatusForbidden)
		return
	}
	// Only allowed while the vault has no owners yet — otherwise a caller
	// with unlock could silently mint a second owner from the login page.
	if exists, err := s.noOwnersYet(); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	} else if !exists {
		http.Error(w, "provisioning already done", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	if label == "" || username == "" || password == "" {
		s.render(w, "login.html", viewData{
			Unlocked: true, NeedsProvision: true, Error: "All fields are required.",
		})
		return
	}
	if password != r.PostForm.Get("password_confirm") {
		s.render(w, "login.html", viewData{
			Unlocked: true, NeedsProvision: true, Error: "The two login passphrases do not match.",
		})
		return
	}

	id := makeULID(s.now())
	auth, err := deriveOwnerLogin(password)
	if err != nil {
		http.Error(w, "kdf", http.StatusInternalServerError)
		return
	}
	err = s.vault.Index().CreateOwner(
		index.Owner{ID: id, Label: label, LoginUsername: username, CreatedAt: s.now().Unix()},
		auth,
	)
	if err != nil {
		s.logger.Error("provision owner", "err", err.Error())
		s.render(w, "login.html", viewData{
			Unlocked: true, NeedsProvision: true,
			Error: "Could not create owner (username may already be in use).",
		})
		return
	}
	// Auto-login.
	sess, err := s.vault.Sessions().Issue(id, clientIP(r))
	if err != nil {
		http.Error(w, "session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, r, sess)
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.vault.IsUnlocked() {
		http.Error(w, "vault locked", http.StatusForbidden)
		return
	}
	if !s.loginLimit.Allow(clientIP(r)) {
		s.render(w, "login.html", viewData{
			Unlocked: true, Error: "Too many attempts. Wait a moment before retrying.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	if username == "" || password == "" {
		s.render(w, "login.html", viewData{Unlocked: true, Error: "Username and passphrase required."})
		return
	}

	// F04: keep the "unknown user" and "wrong password" paths structurally
	// identical, not just approximately so. Fetch either way; on a miss,
	// substitute a sentinel OwnerAuth with the same shape as a real one so
	// PBKDF2 runs with the same iteration count and the compare runs
	// against a same-length hash. The old code ran a dummy PBKDF2 but
	// skipped the ConstantTimeCompare AND the DB round-trip; wall-time
	// still leaked whether a username existed.
	ownerID, auth, err := s.lookupOwnerAuth(username)
	found := err == nil
	if !found {
		auth = sentinelOwnerAuth()
	}
	got := pbkdf2.Key([]byte(password), auth.Salt, auth.Iterations, len(auth.Hash), sha256.New)
	ok := subtle.ConstantTimeCompare(got, auth.Hash) == 1
	if !found || !ok {
		s.render(w, "login.html", viewData{Unlocked: true, Error: "Invalid credentials."})
		return
	}

	sess, err := s.vault.Sessions().Issue(ownerID, clientIP(r))
	if err != nil {
		http.Error(w, "session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, r, sess)
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, _ := s.currentSession(r); sess != nil {
		s.vault.Sessions().Delete(sess.ID)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- authenticated ----------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	view, err := s.buildStatusView(sess.OwnerID)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.render(w, "status.html", viewData{
		Unlocked: true, Authed: true, Status: view,
	})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	// F02: a client that declares a body over the cap is refused before a
	// single byte is read. Chunked or lying clients are still bounded by the
	// MaxBytesReader below, which errors once the cap is passed.
	if r.ContentLength > uploadBodyLimit {
		http.Error(w, "upload exceeds size limit", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, uploadBodyLimit)

	// Stream the multipart body: find the "file" part and hand it directly to
	// ingest, whose staging step is the only copy (to the F01-guarded tmpfs).
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "bad multipart form", http.StatusBadRequest)
		return
	}
	var part *multipart.Part
	for part == nil {
		p, perr := mr.NextPart()
		if perr == io.EOF {
			http.Error(w, "missing 'file' field", http.StatusBadRequest)
			return
		}
		if perr != nil {
			if isBodyTooLarge(perr) {
				http.Error(w, "upload exceeds size limit", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad multipart form", http.StatusBadRequest)
			return
		}
		if p.FormName() == "file" && p.FileName() != "" {
			part = p
			break
		}
		_ = p.Close() // some other field: skip it
	}
	defer part.Close()

	res, err := s.vault.Ingest().IngestReader(sess.OwnerID, ingest.SourceUpload, part.FileName(), part)
	if err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "upload exceeds size limit", http.StatusRequestEntityTooLarge)
			return
		}
		if errors.Is(err, ingest.ErrBusy) {
			http.Error(w, "another upload is being processed; try again in a minute", http.StatusServiceUnavailable)
			return
		}
		s.logger.Warn("upload ingest failed", "owner", sess.OwnerID, "err", err.Error())
		view, _ := s.buildStatusView(sess.OwnerID)
		s.render(w, "status.html", viewData{
			Unlocked: true, Authed: true, Status: view,
			Error: "Ingest failed: " + humanizeIngestErr(err),
		})
		return
	}
	view, _ := s.buildStatusView(sess.OwnerID)
	s.render(w, "status.html", viewData{
		Unlocked: true, Authed: true, Status: view,
		Flash: fmt.Sprintf("Ingested %s (%d bytes, %d tables).",
			shortHash(res.SHA256), res.SizeBytes, len(res.TableCounts)),
	})
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	// Ensure the row belongs to this owner (owner-scoped, per F6).
	backups, err := s.vault.Index().ListBackups(sess.OwnerID)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	var wantSHA string
	found := false
	for _, b := range backups {
		if b.ID == id {
			wantSHA = b.SHA256
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Stream the blob byte-identical (F10 / N8).
	rc, err := openBlob(s.vault, sess.OwnerID, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="sanctum-restore-%s.tryst"`, shortHash(wantSHA)))
	w.Header().Set("X-Sanctum-SHA256", wantSHA)
	if _, err := io.Copy(w, rc); err != nil {
		s.logger.Warn("restore stream truncated", "id", id, "err", err.Error())
		return
	}
	if err := rc.Close(); err != nil {
		// The reader verifies on Close. A hash mismatch here means the on-disk
		// blob has been tampered with — the client has already received the
		// bytes so we can't undo that, but the operator MUST see it.
		s.logger.Error("restore SHA mismatch",
			"owner", sess.OwnerID, "id", id, "err", err.Error())
	}
}

func (s *Server) handlePasswords(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	list, err := s.vault.Index().ListBackupPasswords(sess.OwnerID)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	rows := make([]passwordRow, 0, len(list))
	for _, p := range list {
		row := passwordRow{ID: p.ID, Label: p.Label,
			AddedWhen: time.Unix(p.AddedAt, 0).UTC().Format(time.RFC3339)}
		if p.LastUsedAt != nil {
			row.LastUsedWhen = time.Unix(*p.LastUsedAt, 0).UTC().Format(time.RFC3339)
		} else {
			row.LastUsedWhen = "never"
		}
		rows = append(rows, row)
	}
	s.render(w, "passwords.html", viewData{
		Unlocked: true, Authed: true, Passwords: rows,
	})
}

func (s *Server) handlePasswordAdd(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	pass := r.PostForm.Get("passphrase")
	if label == "" || pass == "" {
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
		return
	}
	err = s.vault.Index().AddBackupPassword(index.BackupPassword{
		ID: makeULID(s.now()), OwnerID: sess.OwnerID, Label: label,
		Passphrase: []byte(pass), AddedAt: s.now().Unix(),
	})
	if err != nil {
		s.logger.Error("add backup password", "err", err.Error())
	}
	http.Redirect(w, r, "/passwords", http.StatusSeeOther)
}

func (s *Server) handlePasswordDelete(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireAuth(w, r)
	if err != nil {
		return
	}
	id := r.PathValue("id")
	// Cheap scope check: don't delete another owner's password entry.
	list, _ := s.vault.Index().ListBackupPasswords(sess.OwnerID)
	found := false
	for _, p := range list {
		if p.ID == id {
			found = true
			break
		}
	}
	if !found {
		http.Redirect(w, r, "/passwords", http.StatusSeeOther)
		return
	}
	if err := s.vault.Index().DeleteBackupPassword(id); err != nil {
		s.logger.Error("delete backup password", "err", err.Error())
	}
	http.Redirect(w, r, "/passwords", http.StatusSeeOther)
}

// --- helpers ----------------------------------------------------------------

// requireAuth checks the session cookie. Redirects to / on failure and
// returns a non-nil error so the caller returns immediately.
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (*session.Session, error) {
	if !s.vault.IsUnlocked() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil, errors.New("vault locked")
	}
	sess, err := s.currentSession(r)
	if err != nil || sess == nil {
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil, errors.New("no session")
	}
	return sess, nil
}

// currentSession returns the session for the request or nil if none/expired.
func (s *Server) currentSession(r *http.Request) (*session.Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil
	}
	mgr := s.vault.Sessions()
	if mgr == nil {
		return nil, nil // vault re-locked mid-flight
	}
	sess, err := mgr.Get(c.Value)
	if err != nil {
		return nil, nil
	}
	return sess, nil
}

// setSessionCookie configures the cookie flags. Secure is on when the
// request came in over TLS (see D-17's residual-risk note for LAN-only HTTP).
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// Shutdown lets the caller (cmd/sanctum) run a graceful shutdown loop.
// Currently a placeholder — the http.Server object is owned by main.
func (s *Server) Shutdown(ctx context.Context) error { return nil }

// clientIP returns the TCP peer's host (rate-limit key and log field).
func clientIP(r *http.Request) string {
	// D03: the peer address only. X-Forwarded-For is attacker-controlled on a
	// direct connection and Sanctum sits behind no proxy (D-12), so honouring it
	// let any client rotate the header to dodge the rate limiters.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func shortHash(hex string) string {
	if len(hex) > 16 {
		return hex[:16]
	}
	return hex
}

func humanizeIngestErr(err error) string {
	switch {
	case errors.Is(err, ingest.ErrDuplicate):
		return "this backup is already stored."
	case errors.Is(err, ingest.ErrNoOwnerPasswords):
		return "add a backup password before uploading."
	case errors.Is(err, ingest.ErrVaultLocked):
		return "the vault re-locked mid-request."
	case errors.Is(err, trystbk.ErrUnsupportedVer):
		return "this backup was made by a newer version of Tryst than this Sanctum understands. Update Sanctum."
	case errors.Is(err, ingest.ErrRejected):
		return "the file is not a valid TRYSTBK1, or no password in your set can open it."
	default:
		return "internal error."
	}
}

// makeULID isn't a real ULID — just a monotonic-shaped id built from unix
// nanoseconds plus a fixed suffix. Sufficient for M4; a real ULID lands
// when we introduce one dependency-wide.
func makeULID(now time.Time) string {
	return fmt.Sprintf("%016x%08x", uint64(now.UnixNano()), uint64(now.Unix())&0xFFFF)
}

// ownerLoginIters is the PBKDF2 iteration count both provisioning and the
// F04 sentinel use. Kept as a shared constant so a bump in one place moves
// the sentinel with it and the timing symmetry survives.
const ownerLoginIters = 600_000

// deriveOwnerLogin runs PBKDF2 for a new owner-login credential (D-14
// chose PBKDF2 for online-guessing resistance).
func deriveOwnerLogin(password string) (index.OwnerAuth, error) {
	var salt [16]byte
	if _, err := readRand(salt[:]); err != nil {
		return index.OwnerAuth{}, err
	}
	hash := pbkdf2.Key([]byte(password), salt[:], ownerLoginIters, 32, sha256.New)
	return index.OwnerAuth{
		KDF:        "pbkdf2-sha256",
		Salt:       salt[:],
		Iterations: ownerLoginIters,
		Hash:       hash,
	}, nil
}

// sentinelOwnerAuth returns an OwnerAuth whose shape matches a real one
// (16-byte salt, ownerLoginIters, 32-byte hash) but whose contents cannot
// be a legitimate credential — the hash is 32 zero bytes, which no live
// PBKDF2 output will ever match under a random salt. Used by the login
// handler on the "unknown user" branch so PBKDF2 + ConstantTimeCompare
// run with identical timing to the real branch.
//
// The Boolean `found` at the caller is what actually gates the login; the
// compare's result on this path is discarded, only its runtime matters.
func sentinelOwnerAuth() index.OwnerAuth {
	// Fixed non-zero salt — a zero salt would still keep the timing right
	// but reads as "obviously placeholder" if it ever leaked into a log.
	var salt [16]byte
	for i := range salt {
		salt[i] = 0x5A
	}
	return index.OwnerAuth{
		KDF:        "pbkdf2-sha256",
		Salt:       salt[:],
		Iterations: ownerLoginIters,
		Hash:       make([]byte, 32),
	}
}

// statusView + passwordRow are the shape the templates consume.
type statusView struct {
	OwnerID        string
	OwnerLabel     string
	BackupCount    int
	TotalSizeHuman string
	NewestAge      string
	Stale          string // non-empty when the newest backup is older than the threshold
	LastVerified   string
	Backups        []backupRow
}

type backupRow struct {
	ID                 string
	When               string
	SizeHuman          string
	TrystSchemaVersion int
	SHAPrefix          string
}

type passwordRow struct {
	ID           string
	Label        string
	AddedWhen    string
	LastUsedWhen string
}

// buildStatusView reads the index and builds the status view for one owner.
func (s *Server) buildStatusView(ownerID string) (*statusView, error) {
	own, err := s.vault.Index().GetOwner(ownerID)
	if err != nil {
		return nil, err
	}
	backups, err := s.vault.Index().ListBackups(ownerID)
	if err != nil {
		return nil, err
	}
	view := &statusView{
		OwnerID:      own.ID,
		OwnerLabel:   own.Label,
		BackupCount:  len(backups),
		LastVerified: "—",
		NewestAge:    "n/a",
	}
	if len(backups) > 0 {
		newest := backups[0]
		view.NewestAge = humanDuration(s.now().Sub(time.Unix(newest.IngestedAt, 0)))
		if newest.VerifiedAt != nil {
			view.LastVerified = time.Unix(*newest.VerifiedAt, 0).UTC().Format(time.RFC3339)
		}
		threshold := s.stalenessDays
		if own.StalenessDays != nil && *own.StalenessDays > 0 {
			threshold = *own.StalenessDays
		}
		age := s.now().Sub(time.Unix(newest.IngestedAt, 0))
		if threshold > 0 && age >= time.Duration(threshold)*24*time.Hour {
			view.Stale = fmt.Sprintf("The newest backup is %s old, past your %d-day limit. Send a fresh backup from Tryst.",
				humanDuration(age), threshold)
		}
	}
	var totalBytes int64
	for _, b := range backups {
		totalBytes += b.SizeBytes
		schemaV := 0
		if b.TrystSchemaVersion != nil {
			schemaV = *b.TrystSchemaVersion
		}
		view.Backups = append(view.Backups, backupRow{
			ID:                 b.ID,
			When:               time.Unix(b.IngestedAt, 0).UTC().Format("2006-01-02 15:04"),
			SizeHuman:          humanBytes(b.SizeBytes),
			TrystSchemaVersion: schemaV,
			SHAPrefix:          shortHash(b.SHA256),
		})
	}
	view.TotalSizeHuman = humanBytes(totalBytes)
	return view, nil
}

func humanBytes(n int64) string {
	const (
		KiB = 1 << 10
		MiB = 1 << 20
		GiB = 1 << 30
	)
	switch {
	case n >= GiB:
		return fmt.Sprintf("%.1f GiB", float64(n)/GiB)
	case n >= MiB:
		return fmt.Sprintf("%.1f MiB", float64(n)/MiB)
	case n >= KiB:
		return fmt.Sprintf("%.1f KiB", float64(n)/KiB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "a moment"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// noOwnersYet is a cheap "is the vault brand new?" check. Used to decide
// whether the landing page shows the first-run provisioning form.
func (s *Server) noOwnersYet() (bool, error) {
	idx := s.vault.Index()
	if idx == nil {
		return false, errors.New("locked")
	}
	var n int
	if err := idx.DB().QueryRow(`SELECT COUNT(*) FROM owner`).Scan(&n); err != nil {
		return false, err
	}
	return n == 0, nil
}

// lookupOwnerAuth fetches (ownerID, credentials) by login_username.
func (s *Server) lookupOwnerAuth(username string) (string, index.OwnerAuth, error) {
	var ownerID string
	var a index.OwnerAuth
	err := s.vault.Index().DB().QueryRow(
		`SELECT id, login_kdf, login_salt, login_iterations, login_hash
		 FROM owner WHERE login_username = ?`, username,
	).Scan(&ownerID, &a.KDF, &a.Salt, &a.Iterations, &a.Hash)
	if err != nil {
		return "", index.OwnerAuth{}, err
	}
	return ownerID, a, nil
}

// isBodyTooLarge returns true when err came from http.MaxBytesReader's cap
// being exceeded. Modern Go returns a *http.MaxBytesError from
// MaxBytesReader, but ParseMultipartForm wraps errors before returning them
// — sometimes as the typed value, sometimes as a formatted string (the
// stdlib's internal sentinel is unexported). We match both surfaces.
func isBodyTooLarge(err error) bool {
	if err == nil {
		return false
	}
	var mbErr *http.MaxBytesError
	if errors.As(err, &mbErr) {
		return true
	}
	return strings.Contains(err.Error(), "http: request body too large")
}

// unused right now but keep the import alive; we might need it for
// side-channel-mitigated comparisons later.
var _ = hex.EncodeToString

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣

// warning builds the banner text for a page, or "" for none. It is derived
// only from timestamps and a day count (never from backup contents).
func (s *Server) warning(data viewData) string {
	if !data.Unlocked {
		if s.lockedSince == nil {
			return ""
		}
		ls := s.lockedSince()
		if ls <= 0 {
			return ""
		}
		d := s.now().Sub(time.Unix(ls, 0))
		if d < time.Hour {
			return ""
		}
		return fmt.Sprintf("This vault has been locked for %s (since %s). Ingest, verification and backup alerts are paused until it is unlocked.",
			humanDuration(d), time.Unix(ls, 0).UTC().Format("2006-01-02"))
	}
	if data.Status != nil && data.Status.Stale != "" {
		return data.Status.Stale
	}
	return ""
}

// firstRunner is implemented by the real vault. It is an optional interface so
// test doubles of Vault keep working.
type firstRunner interface{ FirstRun() bool }

func (s *Server) firstRun() bool {
	if f, ok := s.vault.(firstRunner); ok {
		return f.FirstRun()
	}
	return false
}
