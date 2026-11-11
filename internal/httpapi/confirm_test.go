package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestFirstRunAsksTwiceAndMismatchCreatesNothing(t *testing.T) {
	e := newE2E(t)

	page := do(t, e, "GET", "/", nil, nil).Body.String()
	if !strings.Contains(page, "passphrase_confirm") || !strings.Contains(page, "Create vault") {
		t.Fatalf("a brand-new vault must ask for the passphrase twice:\n%s", page)
	}

	for name, form := range map[string]url.Values{
		"different":       {"passphrase": {"alpha-one"}, "passphrase_confirm": {"alpha-two"}},
		"confirm missing": {"passphrase": {"alpha-one"}},
		"confirm empty":   {"passphrase": {"alpha-one"}, "passphrase_confirm": {""}},
	} {
		rec := do(t, e, "POST", "/unlock", form, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "do not match") {
			t.Fatalf("%s: want a mismatch error, got %d\n%s", name, rec.Code, rec.Body.String())
		}
		if e.v.IsUnlocked() {
			t.Fatalf("%s: a mismatch must not unlock or create the vault", name)
		}
	}

	rec := do(t, e, "POST", "/unlock", url.Values{"passphrase": {"alpha-one"}, "passphrase_confirm": {"alpha-one"}}, nil)
	if rec.Code != http.StatusSeeOther || !e.v.IsUnlocked() {
		t.Fatalf("matching entries must create and unlock: %d", rec.Code)
	}
}

func TestSecondUnlockAsksOnlyOnce(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "alpha-one")
	provisionAndLogin(t, e)
	if err := e.v.Lock(); err != nil {
		t.Fatal(err)
	}
	page := do(t, e, "GET", "/", nil, nil).Body.String()
	if strings.Contains(page, "passphrase_confirm") {
		t.Fatal("an existing vault must not show the confirm box")
	}
	// A wrong passphrase on an existing vault is still a plain failure, never a "mismatch".
	rec := do(t, e, "POST", "/unlock", url.Values{"passphrase": {"nope"}}, nil)
	if !strings.Contains(rec.Body.String(), "Unlock failed") || e.v.IsUnlocked() {
		t.Fatalf("wrong passphrase on an existing vault:\n%s", rec.Body.String())
	}
	// And the right one, with no confirm field, unlocks.
	rec = do(t, e, "POST", "/unlock", url.Values{"passphrase": {"alpha-one"}}, nil)
	if rec.Code != http.StatusSeeOther || !e.v.IsUnlocked() {
		t.Fatalf("correct passphrase must unlock: %d", rec.Code)
	}
}

func TestProvisionRequiresMatchingLoginPassphrase(t *testing.T) {
	e := newE2E(t)
	unlock(t, e, "alpha-one")
	rec := do(t, e, "POST", "/provision", url.Values{
		"label": {"me"}, "username": {"root"}, "password": {"one"}, "password_confirm": {"two"},
	}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "do not match") {
		t.Fatalf("want a mismatch error, got %d\n%s", rec.Code, rec.Body.String())
	}
	if exists, _ := e.srv.noOwnersYet(); !exists {
		t.Fatal("a mismatch must not create an owner")
	}
}
