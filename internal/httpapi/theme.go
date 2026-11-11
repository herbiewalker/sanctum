package httpapi

import (
	_ "embed"
	"net/http"
)

//go:embed static/app.js
var appJS []byte

const themeCookie = "sanctum_theme"

// themeFrom returns the viewer's saved choice: "light", "dark" or "auto".
func themeFrom(r *http.Request) string {
	if r != nil {
		if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
			return c.Value
		}
	}
	return "auto"
}

// nextFor maps a page to the path the theme buttons should return to.
func nextFor(name string) string {
	switch name {
	case "status.html":
		return "/status"
	case "passwords.html":
		return "/passwords"
	}
	return "/"
}

// handleTheme stores the colour-scheme choice in a cookie. It holds no secret
// and works without JavaScript. "auto" clears it so the system setting wins.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	c := &http.Cookie{Name: themeCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, HttpOnly: true}
	switch v := r.PostForm.Get("theme"); v {
	case "light", "dark":
		c.Value, c.MaxAge = v, 365*24*3600
	default:
		c.Value, c.MaxAge = "", -1
	}
	http.SetCookie(w, c)
	next := "/"
	switch r.PostForm.Get("next") {
	case "/status":
		next = "/status"
	case "/passwords":
		next = "/passwords"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleAppJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(appJS)
}
