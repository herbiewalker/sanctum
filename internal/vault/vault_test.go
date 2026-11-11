package vault

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/vaultkey"
)

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// newTestVault builds a Vault backed by t.TempDir() with insecure-for-test
// KDF params, so unlocks are microseconds instead of ~500 ms.
func newTestVault(t *testing.T) *Vault {
	t.Helper()
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	tmpDir := filepath.Join(base, "tmp")

	// Force insecure-for-test KDF params by writing a manifest ourselves
	// before New() has a chance to mint DefaultParams (production strength).
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		LayoutVersion: LayoutVersion,
		KDF:           vaultkey.TestParams(),
		CreatedAt:     1_700_000_000,
	}
	if err := writeManifest(filepath.Join(vaultDir, ManifestFile), m); err != nil {
		t.Fatal(err)
	}

	v, err := New(Paths{
		VaultDir: vaultDir, TmpDir: tmpDir,
		AllowNonTmpfsTmpDir: true, // t.TempDir() is on the test host's real fs
	}, Options{
		Now:              func() time.Time { return time.Unix(1_700_000_000, 0) },
		Logger:           nullLogger(),
		AllowInsecureKDF: true, // TestParams are below the production floor
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// F01: TmpDir is required. An empty TmpDir must NOT silently fall back
// to os.TempDir() — that would put decrypted state on the array in any
// deployment that forgot the tmpfs mount.
func TestNew_RejectsEmptyTmpDir(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Paths{
		VaultDir:            filepath.Join(dir, "vault"),
		TmpDir:              "",
		AllowNonTmpfsTmpDir: true, // proves the missing-field guard fires before the tmpfs guard
	}, Options{Logger: nullLogger()})
	if err == nil {
		t.Fatal("New accepted an empty TmpDir")
	}
}

// F05: swapping the salt inside manifest.json between two unlock cycles
// surfaces as ErrManifestOutOfBand — distinct from ErrBadPassphrase — so
// the operator sees "your manifest changed" rather than blaming their
// passphrase. Round-trips first to produce a real seal, then mutates
// manifest.json, then reloads.
func TestUnlock_TamperedManifestSurfacesOutOfBand_F05(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	// Seed a row so there is a real seal to unseal on round two.
	err := v.Index().CreateOwner(
		index.Owner{ID: "O", Label: "l", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"),
			Iterations: 1, Hash: []byte("h")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(); err != nil {
		t.Fatal(err)
	}

	// Rebuild the vault from a fresh Vault handle, mutating the manifest
	// KDF salt in between. The seal on disk was written against the OLD
	// salt-binding; the new manifest carries a different salt; unseal
	// must trip the F05 pre-check.
	vaultDir := v.paths.VaultDir
	m, _, err := LoadOrCreateManifest(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit of the salt. Any change to the KDF stanza breaks the
	// binding — flipping salt keeps the rest of the shape identical.
	m.KDF.Salt[0] ^= 0x01
	if err := writeManifest(filepath.Join(vaultDir, ManifestFile), m); err != nil {
		t.Fatal(err)
	}

	v2, err := New(Paths{
		VaultDir: vaultDir, TmpDir: v.paths.TmpDir,
		AllowNonTmpfsTmpDir: true,
	}, Options{
		Now:              func() time.Time { return time.Unix(1_700_000_000, 0) },
		Logger:           nullLogger(),
		AllowInsecureKDF: true,
	})
	if err != nil {
		t.Fatalf("New (round 2): %v", err)
	}
	t.Cleanup(func() { _ = v2.Close() })

	err = v2.Unlock("pw")
	if !errors.Is(err, ErrManifestOutOfBand) {
		t.Fatalf("Unlock: err = %v, want ErrManifestOutOfBand", err)
	}
	if v2.IsUnlocked() {
		t.Fatal("tampered-manifest Unlock left the vault unlocked")
	}
}

// F03: A manifest whose KDF params are below the production floor must
// be rejected at Unlock — unless the caller explicitly opts in via
// Options.AllowInsecureKDF (which the surrounding test helpers do). This
// test wires a real Vault WITHOUT the opt-in, writes a TestParams
// manifest, and asserts Unlock refuses with ErrKDFBelowProductionFloor.
func TestUnlock_RejectsBelowProductionFloor_F03(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	tmpDir := filepath.Join(base, "tmp")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Hand-mint an insecure manifest — the same shape a maintainer might
	// accidentally end up with by copying a test scaffold into production.
	m := Manifest{
		LayoutVersion: LayoutVersion,
		KDF:           vaultkey.TestParams(),
		CreatedAt:     1_700_000_000,
	}
	if err := writeManifest(filepath.Join(vaultDir, ManifestFile), m); err != nil {
		t.Fatal(err)
	}
	v, err := New(Paths{
		VaultDir: vaultDir, TmpDir: tmpDir,
		AllowNonTmpfsTmpDir: true,
	}, Options{
		Logger: nullLogger(),
		// Deliberately NOT setting AllowInsecureKDF — this is the check.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	err = v.Unlock("anything")
	if !errors.Is(err, vaultkey.ErrKDFBelowProductionFloor) {
		t.Fatalf("Unlock: err = %v, want ErrKDFBelowProductionFloor", err)
	}
	if v.IsUnlocked() {
		t.Fatal("weak-KDF Unlock left the vault unlocked")
	}
}

// F01: TmpDir must not equal VaultDir. Guarded at both config and vault
// layers; this covers the vault-layer defence for programmatic callers.
func TestNew_RejectsTmpDirEqualToVaultDir(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Paths{
		VaultDir:            dir,
		TmpDir:              dir,
		AllowNonTmpfsTmpDir: true,
	}, Options{Logger: nullLogger()})
	if err == nil {
		t.Fatal("New accepted TmpDir == VaultDir")
	}
}

// A fresh Vault starts LOCKED: Index/Ingest/Sessions are nil, Store is
// available.
func TestNew_StartsLocked(t *testing.T) {
	v := newTestVault(t)
	if v.IsUnlocked() {
		t.Fatal("fresh vault reports unlocked")
	}
	if v.Store() == nil {
		t.Error("Store() nil on fresh vault")
	}
	if v.Index() != nil || v.Ingest() != nil || v.Sessions() != nil {
		t.Error("Index/Ingest/Sessions non-nil while locked")
	}
}

func TestUnlock_HappyPath_FirstRun(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("open-sesame"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("Unlock returned nil but IsUnlocked=false")
	}
	if v.Index() == nil || v.Ingest() == nil || v.Sessions() == nil {
		t.Error("index/ingest/sessions nil after Unlock")
	}
	if v.Index().SchemaVersion() != index.CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d",
			v.Index().SchemaVersion(), index.CurrentSchemaVersion)
	}
}

func TestUnlock_AlreadyUnlockedFailsLoudly(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("pw"); !errors.Is(err, ErrAlreadyUnlocked) {
		t.Errorf("second Unlock: err = %v, want ErrAlreadyUnlocked", err)
	}
}

// The load-bearing round-trip: Unlock, seed a row, Lock, Unlock again with
// the same passphrase, verify the row is still there. Proves the seal ↔
// unseal path holds under real Argon2id-derived-key usage.
func TestUnlockLockUnlock_RoundTripPreservesData(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	err := v.Index().CreateOwner(
		index.Owner{ID: "OWN", Label: "l", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"),
			Iterations: 1, Hash: []byte("h")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if v.IsUnlocked() {
		t.Fatal("Lock returned nil but IsUnlocked=true")
	}
	if v.Index() != nil || v.Ingest() != nil {
		t.Fatal("index/ingest still reachable after Lock")
	}

	if err := v.Unlock("pw"); err != nil {
		t.Fatalf("Unlock (round 2): %v", err)
	}
	got, err := v.Index().GetOwner("OWN")
	if err != nil {
		t.Fatalf("GetOwner after round-trip: %v", err)
	}
	if got.Label != "l" {
		t.Errorf("Label survived as %q, want %q", got.Label, "l")
	}
}

// Wrong passphrase → ErrBadPassphrase, vault stays LOCKED, no partial state.
func TestUnlock_WrongPassphraseAfterSealExists(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("correct"); err != nil {
		t.Fatal(err)
	}
	// Seed something so there is a real seal to compare against on the next
	// unlock; otherwise the second Unlock hits the "no seal on disk" path.
	err := v.Index().CreateOwner(
		index.Owner{ID: "X", Label: "l", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"),
			Iterations: 1, Hash: []byte("h")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(); err != nil {
		t.Fatal(err)
	}

	err = v.Unlock("WRONG")
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err = %v, want ErrBadPassphrase", err)
	}
	if v.IsUnlocked() {
		t.Fatal("wrong-pw Unlock left the vault unlocked")
	}
	// Correct pw must still work.
	if err := v.Unlock("correct"); err != nil {
		t.Fatalf("correct pw after wrong: %v", err)
	}
}

// N17 defence in depth: after Lock, any session issued before is not
// usable. The vault clears the session manager on Lock, and constructs a
// fresh one on the next Unlock.
func TestLock_ClearsSessions_N17(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	sess, err := v.Sessions().Issue("OWNER1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Lock(); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	// Fresh manager — the old session id must not resolve.
	if _, err := v.Sessions().Get(sess.ID); err == nil {
		t.Errorf("stale session %s survived a Lock/Unlock cycle", sess.ID)
	}
}

// N11 close: after Close, vault reports locked and re-open works.
func TestClose_LocksIfNeeded(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if v.IsUnlocked() {
		t.Fatal("Close did not lock")
	}
}

// Ingest calls made after Lock must fail via the Ingest service's own
// Locked flag (defence in depth: nil-check would catch it too).
func TestLock_MarksIngestLocked(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	// Snap a reference like an HTTP handler might have done.
	ing := v.Ingest()
	if err := v.Lock(); err != nil {
		t.Fatal(err)
	}
	if !ing.IsLocked() {
		t.Error("stale ingest reference is not marked Locked after vault.Lock")
	}
}

// Manifest: an unknown layout_version is rejected loudly (a future ADR
// would raise this after writing a migrator; until then, don't guess).
func TestLoadOrCreateManifest_RejectsUnknownLayoutVersion(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		LayoutVersion: LayoutVersion + 100,
		KDF:           vaultkey.TestParams(),
		CreatedAt:     1,
	}
	if err := writeManifest(filepath.Join(dir, ManifestFile), m); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateManifest(dir); err == nil {
		t.Fatal("LoadOrCreateManifest accepted unknown layout_version")
	}
}

// First-run behaviour: no manifest exists, one is minted, subsequent load
// returns the SAME salt (otherwise unlock would derive a different key on
// each start and every stored seal would fail).
func TestLoadOrCreateManifest_FirstRunPersistsSalt(t *testing.T) {
	dir := t.TempDir()
	m1, created, err := LoadOrCreateManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("first LoadOrCreateManifest returned created=false")
	}
	m2, created, err := LoadOrCreateManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("second LoadOrCreateManifest returned created=true")
	}
	if string(m1.KDF.Salt) != string(m2.KDF.Salt) {
		t.Error("salt changed across loads — every unlock would fail on a real vault")
	}
}

// D02: a crash inside SealFile (after seal→prev, before tmp→seal) leaves no
// index.sealed. Unlock must NOT treat that as a fresh vault: it has to
// authenticate against the surviving generation.
func TestUnlock_MissingPrimaryWithPrev_DoesNotFailOpen_D02(t *testing.T) {
	v := newTestVault(t)
	for i := 0; i < 2; i++ { // two cycles so a .prev exists
		if err := v.Unlock("right-pass"); err != nil {
			t.Fatal(err)
		}
		if err := v.Lock(); err != nil {
			t.Fatal(err)
		}
	}
	dir := v.paths.VaultDir
	if err := os.Rename(filepath.Join(dir, "index.sealed"), filepath.Join(dir, "index.sealed.prev")); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock("WRONG-pass"); err == nil {
		t.Fatal("unlock with a wrong passphrase succeeded after the primary seal went missing")
	}
	if v.IsUnlocked() {
		t.Fatal("vault is unlocked after a failed unlock")
	}
	if err := v.Unlock("right-pass"); err != nil {
		t.Fatalf("right passphrase must recover from .prev: %v", err)
	}
}

// D02: the unpromoted .tmp is the newest generation and must be preferred.
func TestUnsealFile_RecoversFromTmpWhenPrimaryMissing_D02(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := index.SealFile(dir, key, nil, []byte("gen1")); err != nil {
		t.Fatal(err)
	}
	if err := index.SealFile(dir, key, nil, []byte("gen2")); err != nil {
		t.Fatal(err)
	}
	// Simulate: tmp written (gen3), seal renamed to prev, crash before tmp→seal.
	sealed3, err := index.SealBytes(key, nil, []byte("gen3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "index.sealed"), filepath.Join(dir, "index.sealed.prev")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.sealed.tmp"), sealed3, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := index.UnsealFile(dir, key, nil)
	if err != nil || string(got) != "gen3" {
		t.Fatalf("want gen3 from tmp, got %q err=%v", got, err)
	}
	// A truncated tmp must fall back to prev, not fail open and not brick.
	if err := os.WriteFile(filepath.Join(dir, "index.sealed.tmp"), sealed3[:len(sealed3)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = index.UnsealFile(dir, key, nil)
	if err != nil || string(got) != "gen2" {
		t.Fatalf("want gen2 from prev after truncated tmp, got %q err=%v", got, err)
	}
}

// D01: committed changes must reach disk without Lock(), so an unclean stop
// does not lose the owner, passwords or backup rows from the session.
func TestCheckpoint_SurvivesUncleanStop_D01(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.Index().CreateOwner(
		index.Owner{ID: "o1", Label: "L", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: make([]byte, 16), Iterations: 1, Hash: make([]byte, 32)},
	); err != nil {
		t.Fatal(err)
	}
	if err := v.Checkpoint(); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if v.FirstRun() {
		t.Fatal("a checkpoint must create the seal (FirstRun should now be false)")
	}
	sealBefore, _ := os.ReadFile(filepath.Join(v.paths.VaultDir, "index.sealed"))
	if err := v.Checkpoint(); err != nil { // unchanged index: must not rewrite
		t.Fatal(err)
	}
	sealAfter, _ := os.ReadFile(filepath.Join(v.paths.VaultDir, "index.sealed"))
	if string(sealBefore) != string(sealAfter) {
		t.Fatal("checkpoint rewrote the seal although nothing changed")
	}

	// "Crash": a second Vault on the same directories, no Lock() on the first.
	v2, err := New(Paths{VaultDir: v.paths.VaultDir, TmpDir: filepath.Join(t.TempDir(), "tmp2"),
		AllowNonTmpfsTmpDir: true}, Options{Logger: nullLogger(), AllowInsecureKDF: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v2.Close() })
	if err := v2.Unlock("pw"); err != nil {
		t.Fatalf("unlock after unclean stop: %v", err)
	}
	if _, err := v2.Index().GetOwner("o1"); err != nil {
		t.Fatalf("owner created before the crash was lost: %v", err)
	}
	if v2.FirstRun() {
		t.Fatal("vault reverted to first-run after an unclean stop")
	}
}
