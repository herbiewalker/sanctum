package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/ingest"
)

// fakeIngester records every IngestFile call. Never fails unless failWith is
// non-nil for that path.
type fakeIngester struct {
	mu       sync.Mutex
	seen     []string
	failWith map[string]error
	result   *ingest.Result
}

func (f *fakeIngester) IngestFile(ownerID, path string) (*ingest.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, path)
	if err, ok := f.failWith[path]; ok {
		return nil, err
	}
	if f.result != nil {
		return f.result, nil
	}
	// Default to a plausible-shaped result so tests that only care about
	// call bookkeeping do not have to set one up.
	return &ingest.Result{BackupID: "B-" + filepath.Base(path), SHA256: "0000000000000000"}, nil
}

func (f *fakeIngester) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// nullLogger discards. Watcher's logs are noisy in tests otherwise.
func nullLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(nullWriter{}, nil))
}

type nullWriter struct{}

func (nullWriter) Write(p []byte) (int, error) { return len(p), nil }

func newTestWatcher(t *testing.T, f *fakeIngester) (*Watcher, string) {
	t.Helper()
	inbox := t.TempDir()
	w, err := New(f, Options{
		InboxDir:  inbox,
		OwnerID:   "OWNER1",
		PollEvery: time.Millisecond, // never used — tests drive PollOnce directly
		Stability: 100 * time.Millisecond,
		Logger:    nullLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w, inbox
}

// A file whose size does not change across polls separated by >= Stability
// gets handed to the ingester exactly once.
func TestWatcher_StableFileIsIngestedOnce(t *testing.T) {
	f := &fakeIngester{result: &ingest.Result{BackupID: "B1", SHA256: "aa"}}
	w, inbox := newTestWatcher(t, f)

	path := filepath.Join(inbox, "a.tryst")
	if err := os.WriteFile(path, []byte("some ciphertext"), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	w.PollOnce(t0) // first-seen
	if f.count() != 0 {
		t.Fatalf("count after first poll = %d, want 0 (needs stability window)", f.count())
	}
	w.PollOnce(t0.Add(50 * time.Millisecond)) // still within stability
	if f.count() != 0 {
		t.Fatalf("count too early = %d, want 0", f.count())
	}
	w.PollOnce(t0.Add(200 * time.Millisecond)) // past stability
	if f.count() != 1 {
		t.Fatalf("count after stable = %d, want 1", f.count())
	}
	// Additional polls must NOT re-ingest.
	w.PollOnce(t0.Add(500 * time.Millisecond))
	w.PollOnce(t0.Add(1 * time.Second))
	if f.count() != 1 {
		t.Errorf("count after extra polls = %d, want 1 (double-ingest!)", f.count())
	}
}

// A file whose size keeps changing (e.g. Syncthing still copying) must NOT
// be handed off. Once it stabilises, it should.
func TestWatcher_GrowingFileWaitsUntilStable(t *testing.T) {
	f := &fakeIngester{}
	w, inbox := newTestWatcher(t, f)

	path := filepath.Join(inbox, "growing.tryst")
	if err := os.WriteFile(path, []byte("small"), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	w.PollOnce(t0)
	// Grow the file: size changes → stability window resets.
	if err := os.WriteFile(path, []byte("bigger content now"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.PollOnce(t0.Add(50 * time.Millisecond))
	if f.count() != 0 {
		t.Fatalf("premature ingest of growing file: count=%d", f.count())
	}
	// Still growing, past what would have been stability if size hadn't changed.
	if err := os.WriteFile(path, []byte("even bigger content again"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.PollOnce(t0.Add(150 * time.Millisecond))
	if f.count() != 0 {
		t.Fatalf("ingest fired while file kept changing: count=%d", f.count())
	}
	// Now it stops growing.
	w.PollOnce(t0.Add(300 * time.Millisecond)) // observe stable size
	w.PollOnce(t0.Add(500 * time.Millisecond)) // past stability
	if f.count() != 1 {
		t.Errorf("count after settling = %d, want 1", f.count())
	}
}

// Non-.tryst files are ignored. Watcher must not care about README, hidden
// files, or partial-transfer artefacts.
func TestWatcher_IgnoresNonTrystFiles(t *testing.T) {
	f := &fakeIngester{}
	w, inbox := newTestWatcher(t, f)

	for _, name := range []string{
		"README.txt", "notes.md", ".hidden", ".syncthing.a.tryst.tmp",
	} {
		if err := os.WriteFile(filepath.Join(inbox, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t0 := time.Now()
	w.PollOnce(t0)
	w.PollOnce(t0.Add(1 * time.Second))
	if f.count() != 0 {
		t.Errorf("watcher handed off non-.tryst files: %d", f.count())
	}
}

// A rejected file (ingest returned an error) is marked done and not
// re-attempted on subsequent polls. That's a deliberate posture: the
// operator moves/renames a failed file, they don't want a hot loop of
// re-attempts filling the log.
func TestWatcher_RejectedFileNotRetried(t *testing.T) {
	f := &fakeIngester{}
	w, inbox := newTestWatcher(t, f)
	badPath := filepath.Join(inbox, "bad.tryst")
	if err := os.WriteFile(badPath, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.failWith = map[string]error{badPath: ingest.ErrRejected}

	t0 := time.Now()
	w.PollOnce(t0)
	w.PollOnce(t0.Add(200 * time.Millisecond)) // stable, ingest fires + fails
	w.PollOnce(t0.Add(400 * time.Millisecond)) // must not retry
	w.PollOnce(t0.Add(600 * time.Millisecond))
	if f.count() != 1 {
		t.Errorf("rejected file was retried: count=%d, want 1", f.count())
	}
}

// A file that appears and then disappears (renamed/moved before stability)
// must not linger in the seen map.
func TestWatcher_DisappearingFilePrunedFromTracking(t *testing.T) {
	f := &fakeIngester{}
	w, inbox := newTestWatcher(t, f)
	path := filepath.Join(inbox, "transient.tryst")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.PollOnce(time.Now())
	// File is now gone.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.PollOnce(time.Now().Add(1 * time.Second))
	// It must NOT be in the tracking map any more (we cannot assert internal
	// map size directly; but the ingester should not be called even if we
	// recreate the file soon and immediately poll).
	if err := os.WriteFile(path, []byte("recreated"), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(2 * time.Second)
	w.PollOnce(t0)                            // fresh first-seen
	w.PollOnce(t0.Add(50 * time.Millisecond)) // within window
	if f.count() != 0 {
		t.Fatalf("premature ingest after re-creation: count=%d", f.count())
	}
	w.PollOnce(t0.Add(200 * time.Millisecond))
	if f.count() != 1 {
		t.Errorf("after re-creation + stability: count=%d, want 1", f.count())
	}
}

// Run() must return when the context is cancelled.
func TestWatcher_RunHonorsCancel(t *testing.T) {
	f := &fakeIngester{}
	w, _ := newTestWatcher(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(20 * time.Millisecond) // let the ticker start
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}
