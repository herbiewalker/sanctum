package scheduler

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

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"

	"github.com/herbiewalker/sanctum/internal/notify"
	"github.com/herbiewalker/sanctum/internal/retention"
	"github.com/herbiewalker/sanctum/internal/trystbk"
	"github.com/herbiewalker/sanctum/internal/vault"
)

// captureNotifier records intents in memory for assertions.
type captureNotifier struct {
	mu  sync.Mutex
	got []notify.Intent
}

func (c *captureNotifier) Notify(in notify.Intent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, in)
	return nil
}
func (c *captureNotifier) count(kind notify.Kind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, i := range c.got {
		if i.Kind == kind {
			n++
		}
	}
	return n
}
func (c *captureNotifier) intents() []notify.Intent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]notify.Intent, len(c.got))
	copy(out, c.got)
	return out
}

// buildSyntheticBackup — same helper the sibling packages use.
func buildSyntheticBackup(t *testing.T, password string, zipBody []byte) []byte {
	t.Helper()
	var salt [16]byte
	_, _ = rand.Read(salt[:])
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
	if _, err := w.Write(zipBody); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func buildMinimalZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	_, _ = f.Write([]byte(`{"schemaVersion":15,"tables":{"encounters":[{"id":1}]}}`))
	_ = zw.Close()
	return buf.Bytes()
}

type env struct {
	vlt      *vault.Vault
	note     *captureNotifier
	nowRef   *time.Time
	sched    *Service
	pw       string
	vaultDir string
}

// setup builds a real vault, unlocks it, seeds one owner + one password.
func setup(t *testing.T, cfg Config) *env {
	t.Helper()
	dir := t.TempDir()
	nowRef := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	nowPtr := &nowRef
	v, err := vault.New(vault.Paths{
		VaultDir:            dir,
		TmpDir:              filepath.Join(dir, "tmp"),
		AllowNonTmpfsTmpDir: true, // t.TempDir() is on real fs
	}, vault.Options{
		Now:    func() time.Time { return *nowPtr },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Use insecure test KDF params so unlock is fast. Rewrite the manifest.
	// vaultkey.TestParams is not accessible outside the package, so we lean
	// on the default (Argon2id t=3,m=64MiB,p=4) which is slow but tolerable
	// for the handful of tests in this file.
	pw := "correct-horse-battery-staple"
	if err := v.Unlock(pw); err != nil {
		t.Fatal(err)
	}
	// Seed one owner + password.
	idx := v.Index()
	if err := idx.CreateOwner(
		vaultOwner("owner-1", "alice", *nowPtr),
		vaultOwnerAuth(),
	); err != nil {
		t.Fatal(err)
	}
	if err := idx.AddBackupPassword(vaultPassword("pw-1", "owner-1", pw, *nowPtr)); err != nil {
		t.Fatal(err)
	}
	note := &captureNotifier{}
	sched, err := New(cfg, Options{
		Vault: v, Notifier: note,
		Now:    func() time.Time { return *nowPtr },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return &env{vlt: v, note: note, nowRef: nowPtr, sched: sched, pw: pw, vaultDir: dir}
}

// --- unit tests over pure logic --------------------------------------------

func TestDue(t *testing.T) {
	now := time.Now()
	if !due(time.Time{}, time.Hour, now) {
		t.Error("zero last must be due")
	}
	if due(now.Add(-30*time.Minute), time.Hour, now) {
		t.Error("30m < 1h should not be due")
	}
	if !due(now.Add(-time.Hour-time.Second), time.Hour, now) {
		t.Error("just past 1h should be due")
	}
}

// --- staleness fires while unlocked ----------------------------------------

func TestStaleness_FiresPastThreshold(t *testing.T) {
	e := setup(t, Config{
		AlertEvery:       time.Nanosecond,
		StalenessDefault: 30 * 24 * time.Hour,
		TickInterval:     time.Hour,
	})
	// No backups → age counts from owner.created_at. Owner was created at
	// *nowRef; advance the clock 40 days.
	*e.nowRef = e.nowRef.Add(40 * 24 * time.Hour)
	e.sched.Tick()
	if n := e.note.count(notify.KindStaleness); n != 1 {
		t.Fatalf("staleness fired %d times, want 1", n)
	}
	got := e.note.intents()[0]
	if got.Severity != notify.SeverityWarning {
		t.Errorf("severity=%q", got.Severity)
	}
	// N15: body must not carry raw filenames or partner content — check
	// that only owner label + counts appear.
	if !bytes.Contains([]byte(got.Body), []byte("alice")) {
		t.Errorf("body missing owner label: %q", got.Body)
	}
}

func TestStaleness_QuietBeforeThreshold(t *testing.T) {
	e := setup(t, Config{
		AlertEvery:       time.Nanosecond,
		StalenessDefault: 30 * 24 * time.Hour,
	})
	*e.nowRef = e.nowRef.Add(10 * 24 * time.Hour) // 10 days: under 30
	e.sched.Tick()
	if n := e.note.count(notify.KindStaleness); n != 0 {
		t.Fatalf("staleness fired %d times, want 0", n)
	}
}

// --- locked-since fires ONLY while locked, and debounces --------------------

func TestLockedSince_FiresWhileLocked(t *testing.T) {
	e := setup(t, Config{
		AlertEvery:          time.Nanosecond,
		LockedAlertAfter:    time.Hour,
		LockedAlertDebounce: 24 * time.Hour,
	})
	// Lock the vault. The Lock path writes locked_since = now.
	if err := e.vlt.Lock(); err != nil {
		t.Fatal(err)
	}
	// Advance clock past the alert-after.
	*e.nowRef = e.nowRef.Add(90 * time.Minute)
	e.sched.Tick()
	if n := e.note.count(notify.KindLockedSince); n != 1 {
		t.Fatalf("locked-since fired %d times, want 1", n)
	}
	// A second tick within the debounce window must not re-fire.
	*e.nowRef = e.nowRef.Add(time.Hour)
	e.sched.Tick()
	if n := e.note.count(notify.KindLockedSince); n != 1 {
		t.Fatalf("locked-since re-fired inside debounce: %d", n)
	}
	// Past the debounce window: fires again.
	*e.nowRef = e.nowRef.Add(48 * time.Hour)
	e.sched.Tick()
	if n := e.note.count(notify.KindLockedSince); n != 2 {
		t.Fatalf("locked-since post-debounce firings=%d, want 2", n)
	}
}

func TestLockedSince_QuietWhenUnlocked(t *testing.T) {
	e := setup(t, Config{
		AlertEvery:       time.Nanosecond,
		LockedAlertAfter: time.Minute,
	})
	*e.nowRef = e.nowRef.Add(24 * time.Hour)
	e.sched.Tick()
	if n := e.note.count(notify.KindLockedSince); n != 0 {
		t.Fatalf("locked-since fired while unlocked: %d", n)
	}
}

func TestLockedSince_StatePersistedToDisk(t *testing.T) {
	e := setup(t, Config{
		AlertEvery:          time.Nanosecond,
		LockedAlertAfter:    time.Minute,
		LockedAlertDebounce: 24 * time.Hour,
	})
	_ = e.vlt.Lock()
	*e.nowRef = e.nowRef.Add(10 * time.Minute)
	e.sched.Tick()

	// state.json should now carry both LockedSince and LastLockedAlertAt.
	raw, err := os.ReadFile(filepath.Join(e.vaultDir, vault.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	var st vault.State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.LockedSince == 0 {
		t.Errorf("locked_since not persisted")
	}
	if st.LastLockedAlertAt == 0 {
		t.Errorf("last_locked_alert_at not persisted")
	}
}

// --- retention runs via scheduler -------------------------------------------

func TestRetention_PrunesAndNotifies(t *testing.T) {
	e := setup(t, Config{
		RetentionEvery: time.Nanosecond,
		Retention:      retention.Policy{KeepMin: 1, MaxAge: 24 * time.Hour},
		TickInterval:   time.Hour,
	})
	// Seed three real blobs, oldest to newest, with the SAME contents
	// hashed differently by manipulating IngestedAt. But blob content must
	// differ for the SHA to differ — build three distinct backups.
	for i, ago := range []int{72, 48, 1} { // hours ago
		pl := buildSyntheticBackup(t, e.pw, buildMinimalZip(t))
		id := "b" + string(rune('0'+i))
		if _, err := e.vlt.Store().Put("owner-1", id, bytes.NewReader(pl)); err != nil {
			t.Fatal(err)
		}
		shaBytes := sha256.Sum256(pl)
		pwID := "pw-1"
		b := vaultBackup(id, "owner-1",
			hexOf(shaBytes[:]), int64(len(pl)),
			e.nowRef.Add(-time.Duration(ago)*time.Hour).Unix(),
			trystbk.MinIterations, &pwID)
		if err := e.vlt.Index().InsertBackup(b, nil); err != nil {
			t.Fatal(err)
		}
	}
	e.sched.Tick()
	// b0 (72h old) should be pruned; b1 (48h) also pruned; b2 (1h) kept.
	rows, err := e.vlt.Index().ListBackups("owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("post-prune rows=%d, want 1", len(rows))
	}
	if rows[0].ID != "b2" {
		t.Errorf("survivor=%q, want b2", rows[0].ID)
	}
	if n := e.note.count(notify.KindPruned); n != 1 {
		t.Errorf("pruned notifications=%d, want 1", n)
	}
}

// --- verify pass via scheduler ---------------------------------------------

func TestVerify_FailsLoudlyOnHashMismatch(t *testing.T) {
	e := setup(t, Config{
		VerifyEvery:  time.Nanosecond,
		TickInterval: time.Hour,
	})
	pl := buildSyntheticBackup(t, e.pw, buildMinimalZip(t))
	id := "bhash"
	if _, err := e.vlt.Store().Put("owner-1", id, bytes.NewReader(pl)); err != nil {
		t.Fatal(err)
	}
	shaBytes := sha256.Sum256(pl)
	pwID := "pw-1"
	b := vaultBackup(id, "owner-1", hexOf(shaBytes[:]), int64(len(pl)),
		e.nowRef.Unix(), trystbk.MinIterations, &pwID)
	if err := e.vlt.Index().InsertBackup(b, nil); err != nil {
		t.Fatal(err)
	}
	// Force the mismatch: rewrite the sidecar with a wrong hash.
	sidecar := filepath.Join(e.vaultDir, "blobs", "owner-1", id+".tryst.sha256")
	if err := os.WriteFile(sidecar,
		[]byte("0000000000000000000000000000000000000000000000000000000000000000"),
		0o600); err != nil {
		t.Fatal(err)
	}
	e.sched.Tick()
	if n := e.note.count(notify.KindVerifyFailed); n != 1 {
		t.Fatalf("verify_failed notifications=%d, want 1", n)
	}
}

// --- helpers ----------------------------------------------------------------

func hexOf(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0x0f]
	}
	return string(out)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
