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

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildHeaderBytes assembles the 29-byte cleartext prefix used to build header
// fixtures. Kept local to this test file so the code path never leaks into
// production and cannot be reused to write a real file.
func buildHeaderBytes(t *testing.T, magic string, version byte, iterations uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(magic)
	b.WriteByte(version)
	b.Write(bytes.Repeat([]byte{0x42}, SaltSize))
	_ = binary.Write(&b, binary.BigEndian, iterations)
	if b.Len() != HeaderSize {
		t.Fatalf("test bug: header assembled to %d bytes", b.Len())
	}
	return b.Bytes()
}

func TestParseHeader_HappyPath(t *testing.T) {
	buf := buildHeaderBytes(t, Magic, FormatVersion1, DefaultIterations)
	h, err := ParseHeader(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if h.Version != FormatVersion1 {
		t.Errorf("Version = %d, want %d", h.Version, FormatVersion1)
	}
	if h.Iterations != DefaultIterations {
		t.Errorf("Iterations = %d, want %d", h.Iterations, DefaultIterations)
	}
	for i, b := range h.Salt {
		if b != 0x42 {
			t.Fatalf("Salt[%d] = %#x, want 0x42", i, b)
			break
		}
	}
}

// A random blob dropped in the inbox must exit with ErrBadMagic before any
// KDF work — this is the cheapest filter and must remain so.
func TestParseHeader_RejectsBadMagic(t *testing.T) {
	buf := buildHeaderBytes(t, "TRYPHOEY", FormatVersion1, DefaultIterations)
	_, err := ParseHeader(bytes.NewReader(buf))
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("err = %v, want ErrBadMagic", err)
	}
}

// Tryst has written container v2 since QOL-5; a real v2 backup was rejected
// by an earlier Sanctum that only knew v1 (found live 2026-11-06).
func TestParseHeader_AcceptsVersion2(t *testing.T) {
	buf := buildHeaderBytes(t, Magic, FormatVersion2, DefaultIterations)
	h, err := ParseHeader(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("v2 header rejected: %v", err)
	}
	if h.Version != FormatVersion2 {
		t.Errorf("Version = %d, want %d", h.Version, FormatVersion2)
	}
}

func TestParseHeader_RejectsUnknownVersion(t *testing.T) {
	for _, v := range []byte{0, 3, 255} {
		buf := buildHeaderBytes(t, Magic, v, DefaultIterations)
		_, err := ParseHeader(bytes.NewReader(buf))
		if !errors.Is(err, ErrUnsupportedVer) {
			t.Errorf("version %d: err = %v, want ErrUnsupportedVer", v, err)
		}
	}
}

// N9: an attacker-controlled iteration count claiming Int.MAX_VALUE (or 0)
// must be rejected outright, not attempted.
func TestParseHeader_RejectsIterationsOutOfBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		iters uint32
	}{
		{"zero", 0},
		{"below minimum", uint32(MinIterations) - 1},
		{"above maximum", uint32(MaxIterations) + 1},
		{"max int32", 1 << 31},
		{"max uint32", 0xFFFFFFFF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := buildHeaderBytes(t, Magic, FormatVersion1, tc.iters)
			_, err := ParseHeader(bytes.NewReader(buf))
			if !errors.Is(err, ErrIterationsRange) {
				t.Fatalf("iters=%d: err = %v, want ErrIterationsRange", tc.iters, err)
			}
		})
	}
}

// A file shorter than the 29-byte header must fail as truncated, not as
// bad magic — the distinction helps operators triage "did a copy fail" vs
// "what is this file".
func TestParseHeader_RejectsTruncated(t *testing.T) {
	full := buildHeaderBytes(t, Magic, FormatVersion1, DefaultIterations)
	for _, n := range []int{0, 1, 8, 9, HeaderSize - 1} {
		t.Run("bytes="+itoa(n), func(t *testing.T) {
			_, err := ParseHeader(bytes.NewReader(full[:n]))
			if !errors.Is(err, ErrHeaderTruncated) {
				t.Fatalf("len=%d: err = %v, want ErrHeaderTruncated", n, err)
			}
		})
	}
}

// After a successful ParseHeader the reader is positioned exactly on the
// first byte of the AEAD stream — the caller can hand it straight to the
// decrypter. Prove this by putting a sentinel just past the header and
// reading it back.
func TestParseHeader_LeavesReaderPositionedAfterHeader(t *testing.T) {
	buf := append(buildHeaderBytes(t, Magic, FormatVersion1, DefaultIterations),
		'S', 'E', 'N', 'T', 'I', 'N', 'E', 'L')
	r := bytes.NewReader(buf)
	if _, err := ParseHeader(r); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, 8)
	if _, err := r.Read(rest); err != nil {
		t.Fatalf("read after header: %v", err)
	}
	if string(rest) != "SENTINEL" {
		t.Fatalf("post-header bytes = %q, want SENTINEL", rest)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
