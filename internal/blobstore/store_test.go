package blobstore

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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// newTempStore builds a Store rooted in t.TempDir(); the OS cleans up.
func newTempStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestPut_WritesBlobAndSidecar_ReturnsSHA(t *testing.T) {
	s := newTempStore(t)
	payload := []byte("this is a fake TRYSTBK1 blob")
	want := sha256.Sum256(payload)

	sum, err := s.Put("ownerA", "01AAA", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !bytes.Equal(sum, want[:]) {
		t.Errorf("Put returned %x, want %x", sum, want)
	}

	// The final file exists and is exactly the payload.
	blob := filepath.Join(s.Root(), "ownerA", "01AAA.tryst")
	got, err := os.ReadFile(blob)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("stored bytes differ from input")
	}

	// Sidecar carries the same hash as hex.
	sidecar := blob + ".sha256"
	side, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if got, wantHex := string(bytes.TrimSpace(side)), hex.EncodeToString(want[:]); got != wantHex {
		t.Errorf("sidecar = %q, want %q", got, wantHex)
	}
}

// D-11: blobs are immutable. A second Put with the same id must fail rather
// than silently overwrite the first.
func TestPut_RejectsDuplicate(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Put("o", "id1", bytes.NewReader([]byte("v1"))); err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	_, err := s.Put("o", "id1", bytes.NewReader([]byte("v2 attempt")))
	if !errors.Is(err, ErrBlobExists) {
		t.Fatalf("Put #2: err = %v, want ErrBlobExists", err)
	}
	// The original bytes must be intact.
	r, err := s.Get("o", "id1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(r)
	if err := r.Close(); err != nil {
		t.Fatalf("Close (verify): %v", err)
	}
	if string(got) != "v1" {
		t.Errorf("bytes = %q, want %q — duplicate Put silently mutated", got, "v1")
	}
}

func TestPut_NoTempLingersOnSuccess(t *testing.T) {
	s := newTempStore(t)
	_, err := s.Put("o", "abc", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ents, err := os.ReadDir(filepath.Join(s.Root(), "o"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("tmp file lingered: %q", e.Name())
		}
	}
}

// Get reads a blob and verifies its SHA-256 on Close.
func TestGet_VerifiesOnClose(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Put("o", "b1", bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	r, err := s.Get("o", "b1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close (verify): %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("bytes = %q, want %q", got, "hello")
	}
}

// D-11 + N6: a byte flipped on the array must fail verification. This is the
// core tamper-evidence guarantee — forced to fire per principle 12.
func TestGet_DetectsTampering(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Put("o", "b2", bytes.NewReader([]byte("original payload"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	blob := filepath.Join(s.Root(), "o", "b2.tryst")
	raw, _ := os.ReadFile(blob)
	raw[0] ^= 0x01
	if err := os.WriteFile(blob, raw, 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	r, err := s.Get("o", "b2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, _ = io.ReadAll(r)
	err = r.Close()
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Close: err = %v, want ErrHashMismatch (tamper undetected!)", err)
	}
}

// Verify() re-hashes without the caller having to plumb io.Copy.
func TestVerify_MatchesGetSemantics(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Put("o", "b3", bytes.NewReader([]byte("clean"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Verify("o", "b3"); err != nil {
		t.Fatalf("Verify (should pass): %v", err)
	}

	// Corrupt sidecar → verify fails.
	sidecar := filepath.Join(s.Root(), "o", "b3.tryst.sha256")
	os.WriteFile(sidecar, []byte("dead"+string(make([]byte, 60))+"\n"), 0o644)
	if err := s.Verify("o", "b3"); err == nil {
		t.Fatal("Verify accepted a bogus sidecar")
	}
}

func TestGet_MissingBlob(t *testing.T) {
	s := newTempStore(t)
	_, err := s.Get("o", "nope")
	if err == nil {
		t.Fatal("Get on missing blob returned nil error")
	}
}

func TestList_ScansOnlyValidBlobs(t *testing.T) {
	s := newTempStore(t)
	_, _ = s.Put("o", "id1", bytes.NewReader([]byte("a")))
	_, _ = s.Put("o", "id2", bytes.NewReader([]byte("bb")))

	// Drop some junk in the owner dir — must be ignored.
	ownerDir := filepath.Join(s.Root(), "o")
	_ = os.WriteFile(filepath.Join(ownerDir, "README.txt"), []byte("junk"), 0o644)
	_ = os.WriteFile(filepath.Join(ownerDir, ".hidden.tryst"), []byte("x"), 0o644)

	entries, err := s.List("o")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
}

func TestList_MissingSidecarIsAnError(t *testing.T) {
	s := newTempStore(t)
	_, _ = s.Put("o", "b1", bytes.NewReader([]byte("x")))
	// Remove the sidecar to simulate on-disk corruption.
	_ = os.Remove(filepath.Join(s.Root(), "o", "b1.tryst.sha256"))
	_, err := s.List("o")
	if err == nil {
		t.Fatal("List did not surface missing sidecar")
	}
}

func TestPut_RejectsInvalidIDs(t *testing.T) {
	s := newTempStore(t)
	for _, id := range []string{"", "../escape", "has space", "has/slash", `has\backslash`, "has:colon"} {
		if _, err := s.Put("o", id, bytes.NewReader([]byte("x"))); err == nil {
			t.Errorf("Put(%q) accepted; want ErrInvalidID", id)
		}
	}
}

func TestListOwners(t *testing.T) {
	s := newTempStore(t)
	_, _ = s.Put("alice", "b1", bytes.NewReader([]byte("x")))
	_, _ = s.Put("bob", "b1", bytes.NewReader([]byte("y")))

	// A tmp/hidden dir must be skipped.
	_ = os.MkdirAll(filepath.Join(s.Root(), ".hidden"), 0o755)

	owners, err := s.ListOwners()
	if err != nil {
		t.Fatalf("ListOwners: %v", err)
	}
	m := map[string]bool{}
	for _, o := range owners {
		m[o] = true
	}
	if !m["alice"] || !m["bob"] {
		t.Errorf("ListOwners = %v, want alice+bob", owners)
	}
	if m[".hidden"] {
		t.Error(".hidden dir was included in owner list")
	}
}

// N1-adjacent: after a Put of a ciphertext blob, nothing under vault/ reads
// as plaintext ZIP magic. blobstore never sees plaintext, but this guard
// asserts the property mechanically on the storage layer — it's the check
// scripts/guards.sh will call once M3 has a real ingest path.
func TestPut_LeavesNoZipMagicOnDisk(t *testing.T) {
	s := newTempStore(t)
	// Put some ciphertext-shaped garbage; the important thing is that the
	// walker below finds no PK\x03\x04 anywhere.
	ct := make([]byte, 4096)
	for i := range ct {
		ct[i] = byte(i * 17)
	}
	if _, err := s.Put("o", "b1", bytes.NewReader(ct)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	zipMagic := []byte{'P', 'K', 0x03, 0x04}
	err := filepath.Walk(s.Root(), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, zipMagic) {
			t.Errorf("file %q contains ZIP magic — plaintext leaked to array?", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
