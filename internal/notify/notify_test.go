package notify

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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func TestFileDrop_WritesAtomicIntent(t *testing.T) {
	dir := t.TempDir()
	n, err := NewFileDropNotifier(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	in := Intent{
		Severity: SeverityWarning,
		Kind:     KindStaleness,
		Subject:  "Sanctum: owner backup is stale",
		Body:     "No backup in 31 days.",
	}
	if err := n.Notify(in); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(dir, "pending")
	entries, err := os.ReadDir(pending)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 file, got %d", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
		t.Fatalf("bad filename: %q", name)
	}
	raw, err := os.ReadFile(filepath.Join(pending, name))
	if err != nil {
		t.Fatal(err)
	}
	var back Intent
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("intent isn't valid json: %v", err)
	}
	if back.Schema != SchemaVersion {
		t.Errorf("schema = %d, want %d", back.Schema, SchemaVersion)
	}
	if back.At == 0 {
		t.Errorf("at not populated")
	}
	if back.Subject != in.Subject {
		t.Errorf("subject roundtrip: %q vs %q", back.Subject, in.Subject)
	}
}

func TestFileDrop_ForcesFilenameOrdering(t *testing.T) {
	dir := t.TempDir()
	n, err := NewFileDropNotifier(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := n.Notify(Intent{
			Severity: SeverityNormal,
			Kind:     KindLockedSince,
			Subject:  "s",
			Body:     "b",
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 files, got %d", len(entries))
	}
	// os.ReadDir sorts by name; check that they're in monotonic order and
	// contain per-file counters (000001, 000002, 000003).
	for i, e := range entries {
		want := "0000" + string(rune('0'+i+1)) + "-locked_since.json"
		if !strings.Contains(e.Name(), want[3:]) {
			t.Errorf("file %d name=%q missing marker %q", i, e.Name(), want)
		}
	}
}

func TestFileDrop_RejectsInvalidIntents(t *testing.T) {
	dir := t.TempDir()
	n, err := NewFileDropNotifier(dir, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   Intent
	}{
		{"empty severity", Intent{Kind: KindStaleness, Subject: "s"}},
		{"bad severity", Intent{Severity: "urgent", Kind: KindStaleness, Subject: "s"}},
		{"empty kind", Intent{Severity: SeverityNormal, Subject: "s"}},
		{"bad kind", Intent{Severity: SeverityNormal, Kind: "boom", Subject: "s"}},
		{"empty subject", Intent{Severity: SeverityNormal, Kind: KindStaleness}},
		{"oversize body", Intent{
			Severity: SeverityNormal, Kind: KindStaleness, Subject: "s",
			Body: strings.Repeat("x", MaxBodyBytes+1),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := n.Notify(c.in); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
	// And nothing should have been written.
	entries, err := os.ReadDir(filepath.Join(dir, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected intents left %d files behind", len(entries))
	}
}

func TestFileDrop_EmptyDirRejected(t *testing.T) {
	if _, err := NewFileDropNotifier("", nil); err == nil {
		t.Fatal("want error on empty dir")
	}
}

func TestNullNotifier_NeverFails(t *testing.T) {
	if err := (NullNotifier{}).Notify(Intent{}); err != nil {
		t.Fatalf("null notifier: %v", err)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
