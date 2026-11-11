package retention

import (
	"errors"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/index"
)

func mkBackup(id string, ingestedAtDaysAgo int, now time.Time) index.Backup {
	return index.Backup{
		ID:         id,
		OwnerID:    "owner-1",
		SHA256:     "abcdef" + id + "0123456789",
		SizeBytes:  1024,
		IngestedAt: now.Add(-time.Duration(ingestedAtDaysAgo) * 24 * time.Hour).Unix(),
		Source:     "inbox",
		BlobPath:   "owner-1/" + id + ".tryst",
	}
}

func TestDecide_NewestIsAlwaysKept(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	// One very old backup, no younger ones.
	backups := []index.Backup{mkBackup("a", 400, now)}
	got := Decide(backups, Policy{KeepMin: 1, MaxAge: 30 * 24 * time.Hour}, now)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Prune {
		t.Fatalf("newest was pruned: %+v", got[0])
	}
	if got[0].Reason != "newest" {
		t.Errorf("reason=%q, want newest", got[0].Reason)
	}
}

func TestDecide_KeepMinAndMaxAgeBothRespected(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	backups := []index.Backup{
		mkBackup("a", 1, now),   // newest, always kept
		mkBackup("b", 5, now),   // young enough, within max_age
		mkBackup("c", 40, now),  // beyond max_age but keep_min=3 saves it
		mkBackup("d", 100, now), // beyond both → prune
		mkBackup("e", 200, now), // beyond both → prune
	}
	got := Decide(backups, Policy{KeepMin: 3, MaxAge: 30 * 24 * time.Hour}, now)
	if len(got) != 5 {
		t.Fatalf("len=%d", len(got))
	}
	reasons := map[string]string{}
	for _, d := range got {
		reasons[d.Backup.ID] = d.Reason
	}
	if reasons["a"] != "newest" {
		t.Errorf("a: %q", reasons["a"])
	}
	if reasons["b"] != "within_keep_min" {
		t.Errorf("b: %q", reasons["b"])
	}
	if reasons["c"] != "within_keep_min" {
		t.Errorf("c: %q", reasons["c"])
	}
	// d and e must be pruned.
	pruned := map[string]bool{}
	for _, d := range got {
		if d.Prune {
			pruned[d.Backup.ID] = true
		}
	}
	if !pruned["d"] || !pruned["e"] {
		t.Errorf("want d and e pruned; got %v", pruned)
	}
	if pruned["a"] || pruned["b"] || pruned["c"] {
		t.Errorf("kept-set had a prune: %v", pruned)
	}
}

func TestDecide_EmptyPolicyPrunesNothing(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	backups := []index.Backup{
		mkBackup("a", 1, now),
		mkBackup("b", 500, now),
	}
	got := Decide(backups, Policy{}, now)
	for _, d := range got {
		if d.Prune {
			t.Errorf("empty policy pruned %s", d.Backup.ID)
		}
	}
}

func TestDecide_MaxAgeAloneKeepsOldWhenOldest(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	// All backups older than max_age, but the newest is still kept because
	// it's the newest — no policy should ever empty a vault.
	backups := []index.Backup{
		mkBackup("a", 100, now),
		mkBackup("b", 200, now),
	}
	got := Decide(backups, Policy{MaxAge: 30 * 24 * time.Hour}, now)
	if got[0].Prune {
		t.Fatalf("newest pruned despite being newest")
	}
	if !got[1].Prune {
		t.Fatalf("older not pruned; got %+v", got[1])
	}
}

// --- Apply ------------------------------------------------------------------

type fakeDeleter struct {
	deleted []string
	failOn  string
}

func (f *fakeDeleter) Delete(ownerID, id string) error {
	if id == f.failOn {
		return errors.New("boom")
	}
	f.deleted = append(f.deleted, ownerID+"/"+id)
	return nil
}

func newTestIndex(t *testing.T) *index.Index {
	t.Helper()
	idx, err := index.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	// Seed an owner (retention doesn't touch owner rows; needed for the FK).
	if err := idx.CreateOwner(
		index.Owner{ID: "owner-1", Label: "test", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte{1}, Iterations: 1, Hash: []byte{1}},
	); err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestApply_DeletesAndLogsAndSurvivesOneFailure(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	idx := newTestIndex(t)
	backups := []index.Backup{
		mkBackup("aaa", 1, now),
		mkBackup("bbb", 100, now),
		mkBackup("ccc", 200, now),
	}
	for _, b := range backups {
		if err := idx.InsertBackup(b, nil); err != nil {
			t.Fatal(err)
		}
	}
	decisions := Decide(backups, Policy{KeepMin: 1, MaxAge: 30 * 24 * time.Hour}, now)
	// Sanity: exactly two should be marked prune.
	pruneCount := 0
	for _, d := range decisions {
		if d.Prune {
			pruneCount++
		}
	}
	if pruneCount != 2 {
		t.Fatalf("expected 2 prunes, got %d", pruneCount)
	}
	// Make one of them fail so we exercise the survive-and-continue path.
	fail := ""
	for _, d := range decisions {
		if d.Prune {
			fail = d.Backup.ID
			break
		}
	}
	f := &fakeDeleter{failOn: fail}
	n, err := Apply(decisions, "owner-1", Options{
		Store: f, Index: idx, Now: func() time.Time { return now },
	})
	if err == nil {
		t.Fatal("expected error surfaced")
	}
	if n != 1 {
		t.Fatalf("pruned=%d, want 1 (one succeeded, one failed)", n)
	}
	// Index should now have exactly two rows (newest + the failed one).
	rows, err := idx.ListBackups("owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("index rows=%d, want 2", len(rows))
	}
	// One pruned event must be recorded.
	var evCount int
	if err := idx.DB().QueryRow(`SELECT COUNT(*) FROM event WHERE kind='pruned'`).Scan(&evCount); err != nil {
		t.Fatal(err)
	}
	if evCount != 1 {
		t.Errorf("pruned events=%d, want 1", evCount)
	}
}

func TestApply_ErrorsOnMissingDeps(t *testing.T) {
	if _, err := Apply(nil, "owner-1", Options{}); err == nil {
		t.Fatal("want error when Store/Index nil")
	}
}
