package ingest

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

// TestGuard_NoPlaintextAfterIngest is the runtime check behind scripts/guards.sh
// no-plaintext (hard constraint 2 / N1).
//
// It runs a full ingest against a temp vault whose plaintext data.json holds
// deliberately identifiable sentinel bytes, then walks the vault dir asserting:
//
//   (a) no file starts with or contains the ZIP magic PK\x03\x04
//   (b) no file starts with the JSON open sequence '{"'
//   (c) no file contains the plaintext sentinel we planted in data.json
//
// If any of these fires, hard constraint 2 has been violated — the ingest
// pipeline is somehow writing decrypted bytes out to the vault dir.
//
// The staging tmpfs is NOT scanned. That directory is expected to hold
// plaintext while an ingest is in flight (bounded by MaxBackupBytes,
// unlinked before return). The whole point of the design is that plaintext
// exists only in tmpfs, never on the array — so the assertion is specifically
// about the vault dir.

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/herbiewalker/sanctum/internal/trystbk"
)

// PlaintextSentinel is a sentinel string that appears inside the plaintext
// data.json we ingest. The vault-dir walk must NOT find it anywhere; if it
// does, plaintext has leaked past the AEAD boundary.
const PlaintextSentinel = "SANCTUM_GUARD_NO_PLAINTEXT_SENTINEL_98QK4LZ"

func TestGuard_NoPlaintextAfterIngest(t *testing.T) {
	s := newSetup(t)

	// data.json carries the sentinel in an encounter row so that IF ingest
	// ever writes decrypted bytes to disk, the sentinel is what we'd see.
	dataJSON := `{
	  "schemaVersion": 15,
	  "tables": {
	    "encounters": [{"id":1,"note":"` + PlaintextSentinel + `"}]
	  }
	}`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	f.Write([]byte(dataJSON))
	_ = zw.Close()

	blob := buildSyntheticBackup(t, s.pw, buf.Bytes())
	if _, err := s.svc.IngestReader(s.ownerID, SourceInbox, "guard.tryst",
		bytes.NewReader(blob)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	zipMagic := []byte{'P', 'K', 0x03, 0x04}
	sentinel := []byte(PlaintextSentinel)
	jsonOpen := []byte(`{"`)

	err := filepath.Walk(s.vaultDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		// Sidecars are hex text (they carry SHA-256 as ASCII) and are
		// exempt from the JSON-open check but not from ZIP or sentinel.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, zipMagic) {
			t.Errorf("%s: contains ZIP magic — plaintext leaked to vault dir", path)
		}
		if bytes.Contains(data, sentinel) {
			t.Errorf("%s: contains data.json sentinel — plaintext leaked", path)
		}
		if len(data) >= 2 && bytes.HasPrefix(data, jsonOpen) {
			t.Errorf("%s: starts with JSON open — plaintext leaked to vault dir", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
