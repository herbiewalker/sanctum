package trystbk

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

// Interop against a REAL Tryst backup.
//
// This is the test that closes residual risk R6 (docs/THREAT_MODEL.md) and
// OPEN_LOOPS OL-8: until it has run against a genuine .tryst file produced by
// the actual app, D-6's choice to reimplement the container from the spec is
// a claim rather than a fact.
//
// The fixtures never live in the repo (hard constraint 4 — real intimacy
// data). This test reads paths from env vars and SKIPS if none are set,
// which is the correct behaviour on CI and on any dev machine that does not
// hold the user's real backups.
//
// To run locally:
//
//	# smallest fixture first (fast; single-segment ciphertext)
//	SANCTUM_TEST_FIXTURE=<path-to-a-real-backup>.tryst \
//	SANCTUM_TEST_PASSWORD=<the password Tryst used to encrypt it> \
//	go test ./internal/trystbk/ -run TestInterop -v
//
// If the password is wrong the test fails with ErrWrongPassword — that is a
// setup issue, not a code issue. If the format changed under us it will fail
// with a parse error and the failure message points to the spec.

import (
	"os"
	"testing"
)

func TestInterop_RealBackup(t *testing.T) {
	path := os.Getenv("SANCTUM_TEST_FIXTURE")
	pw := os.Getenv("SANCTUM_TEST_PASSWORD")
	if path == "" || pw == "" {
		t.Skip("set SANCTUM_TEST_FIXTURE and SANCTUM_TEST_PASSWORD to run against a real backup")
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	m, err := Open(f, pw)
	if err != nil {
		t.Fatalf("Open real backup: %v", err)
	}

	// Structural assertions — no claim about specific row counts because
	// those depend on which fixture you point at. Everything below has to be
	// true of ANY valid TRYSTBK1 v1 backup.
	if m.Version != FormatVersion1 {
		t.Errorf("Version = %d, want %d", m.Version, FormatVersion1)
	}
	if m.Iterations < MinIterations || m.Iterations > MaxIterations {
		t.Errorf("Iterations = %d, out of accepted bounds", m.Iterations)
	}
	if m.TrystSchemaVersion <= 0 {
		t.Errorf("TrystSchemaVersion = %d, want > 0 (real Tryst is on v15+)", m.TrystSchemaVersion)
	}
	if len(m.TableCounts) == 0 {
		t.Error("TableCounts empty — data.json parsed to nothing")
	}

	// Log what we read; a failing run's log is the audit trail. Neutral
	// output only (D-10 / N15) — schema version and count summary, never a
	// table's row values, never a partner name.
	t.Logf("interop OK: container v%d, KDF iters=%d, Tryst schema v%d",
		m.Version, m.Iterations, m.TrystSchemaVersion)
	t.Logf("tables: %d distinct; media entries=%d, media bytes=%d",
		len(m.TableCounts)-boolAsInt(hasKey(m.TableCounts, SyntheticMediaKey)),
		m.TableCounts[SyntheticMediaKey], m.MediaBytes)
}

func hasKey(m map[string]int, k string) bool { _, ok := m[k]; return ok }
func boolAsInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
