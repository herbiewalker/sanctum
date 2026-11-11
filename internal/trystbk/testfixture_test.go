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

// Test-only synthetic TRYSTBK1 writer.
//
// This exists ONLY to build controlled fixtures for the tests. It is deliberately
// private to the trystbk package: the outside world has no business writing
// TRYSTBK1 files (Tryst is the sole writer, D-1). If ever moved out of _test.go
// it becomes a supply-chain risk — grep before letting that happen.

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// syntheticBackup builds a valid TRYSTBK1 v1 file around zipBody, encrypted
// under password with the given iteration count. Salt is filled randomly.
//
// Pass iterations at the lower bound (MinIterations) in tests; anything larger
// just makes the suite slow without exercising new code paths.
func syntheticBackup(t *testing.T, password string, iterations int, zipBody []byte) []byte {
	t.Helper()
	return syntheticBackupVersion(t, FormatVersion1, password, iterations, zipBody)
}

// syntheticBackupVersion is syntheticBackup with an explicit container version
// byte. Tryst has written version 2 since QOL-5; the crypto is identical to v1.
func syntheticBackupVersion(t *testing.T, version byte, password string, iterations int, zipBody []byte) []byte {
	t.Helper()

	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Header: magic || version || salt || iterations(be32)
	var header bytes.Buffer
	header.WriteString(Magic)
	header.WriteByte(version)
	header.Write(salt[:])
	_ = binary.Write(&header, binary.BigEndian, uint32(iterations))
	if header.Len() != HeaderSize {
		t.Fatalf("header assembled to %d bytes, want %d", header.Len(), HeaderSize)
	}

	// Encrypt body under the same primitive the reader uses. If the writer's
	// crypto ever drifted from the reader's, this whole test suite would
	// falsely pass — that's why they are literally the same call.
	key := pbkdf2.Key([]byte(password), salt[:], iterations, KeySizeBytes, sha256.New)
	aead, err := subtle.NewAESGCMHKDF(key, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	var out bytes.Buffer
	out.Write(header.Bytes())
	w, err := aead.NewEncryptingWriter(&out, []byte(AssociatedData))
	if err != nil {
		t.Fatalf("enc writer: %v", err)
	}
	if _, err := w.Write(zipBody); err != nil {
		t.Fatalf("enc write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("enc close: %v", err)
	}
	return out.Bytes()
}

// buildZip builds an in-memory ZIP with the given entries. Zero method =
// zip.Store; a nil body produces a directory entry. Tests that need a
// non-standard compression method (e.g. to prove N19) build the ZIP inline
// and skip this helper.
type zipEntry struct {
	name   string
	body   []byte
	method uint16
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: e.method}
		f, err := w.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("CreateHeader %q: %v", e.name, err)
		}
		// A directory entry (name ending in "/") is metadata only in ZIP —
		// archive/zip returns an error if you try to Write to it. Tests can
		// still include directory entries by leaving body nil.
		if len(e.body) > 0 {
			if _, err := f.Write(e.body); err != nil {
				t.Fatalf("Write %q: %v", e.name, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// minimalDataJSON returns a tiny valid data.json for tests that only care
// about the schema version + a couple of table counts.
func minimalDataJSON(schemaVersion int) []byte {
	return []byte(`{
  "schemaVersion": ` + itoa(schemaVersion) + `,
  "tables": {
    "encounters": [ {"id":1}, {"id":2}, {"id":3} ],
    "partners":   [ {"id":1} ]
  }
}`)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(append(b, digits[i:]...))
}

// assertNoErr is used by tests that need to fail fast on setup errors.
func assertNoErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
