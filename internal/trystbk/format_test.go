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
	"crypto/sha256"
	"io"
	"testing"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// The header offsets are used to slice a byte array; if the parts and the total
// ever disagree the reader silently starts the AEAD stream at the wrong offset,
// which surfaces as "wrong password" rather than "bad code".
func TestHeaderSizeMatchesItsParts(t *testing.T) {
	if got, want := MagicSize+VersionSize+SaltSize+IterationsSize, HeaderSize; got != want {
		t.Fatalf("header parts sum to %d, HeaderSize is %d", got, want)
	}
	if got, want := HeaderSize, 29; got != want {
		t.Fatalf("HeaderSize = %d, spec says %d", got, want)
	}
	if got, want := len(Magic), MagicSize; got != want {
		t.Fatalf("len(Magic) = %d, MagicSize = %d", got, want)
	}
}

func TestIterationBoundsBracketTrystsDefault(t *testing.T) {
	if DefaultIterations < MinIterations || DefaultIterations > MaxIterations {
		t.Fatalf("Tryst's default %d falls outside the accepted bounds [%d, %d] — "+
			"real backups would be rejected", DefaultIterations, MinIterations, MaxIterations)
	}
}

// This is the load-bearing assumption behind ADR D-6: that tink-go can build an
// AES-GCM-HKDF streaming primitive from RAW key material (a PBKDF2 output),
// with no Tink keyset involved — the same way Tryst's Java side does it.
//
// If this test fails, D-6 is wrong and the stack decision has to be revisited,
// so it is worth having before M1 builds anything on top of it. It proves the
// primitive round-trips with Tryst's exact parameters; it does NOT prove
// wire-compatibility with the app, which only a real .tryst file can show
// (M1 exit criterion / residual risk R6).
func TestTinkStreamingPrimitiveRoundTripsWithTrystParameters(t *testing.T) {
	key := pbkdf2.Key([]byte("correct horse battery staple"),
		bytes.Repeat([]byte{0xAB}, SaltSize), MinIterations, KeySizeBytes, sha256.New)

	if len(key) != KeySizeBytes {
		t.Fatalf("PBKDF2 produced %d bytes, want %d", len(key), KeySizeBytes)
	}

	aead, err := subtle.NewAESGCMHKDF(key, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF with Tryst's parameters: %v — ADR D-6 does not hold", err)
	}

	// Larger than one segment, so segment chaining is actually exercised rather
	// than a single-segment happy path.
	plaintext := bytes.Repeat([]byte("sanctum"), (SegmentSize/7)+1024)
	ad := []byte(AssociatedData)

	var ct bytes.Buffer
	w, err := aead.NewEncryptingWriter(&ct, ad)
	if err != nil {
		t.Fatalf("NewEncryptingWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := aead.NewDecryptingReader(bytes.NewReader(ct.Bytes()), ad)
	if err != nil {
		t.Fatalf("NewDecryptingReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

// Tamper-evidence (ADR D-11) is a claim until it is forced to fail. Principle
// 12: a safety mechanism that has never fired is not a safety mechanism.
func TestFlippedByteFailsAuthentication(t *testing.T) {
	key := pbkdf2.Key([]byte("pw"), bytes.Repeat([]byte{0x01}, SaltSize),
		MinIterations, KeySizeBytes, sha256.New)
	aead, err := subtle.NewAESGCMHKDF(key, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF: %v", err)
	}
	ad := []byte(AssociatedData)

	var ct bytes.Buffer
	w, _ := aead.NewEncryptingWriter(&ct, ad)
	_, _ = w.Write([]byte("a backup that must not be silently modifiable"))
	_ = w.Close()

	corrupt := bytes.Clone(ct.Bytes())
	corrupt[len(corrupt)-1] ^= 0x01 // flip one bit in the final segment

	r, err := aead.NewDecryptingReader(bytes.NewReader(corrupt), ad)
	if err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("a flipped byte decrypted successfully — tamper-evidence (D-11) does not hold")
		}
	}
}

// The associated data is what binds a ciphertext to *this* format. If it were
// ignored, a stream lifted from some other Tink-encrypted product would decrypt
// here. Confirm it is actually enforced.
func TestWrongAssociatedDataFailsAuthentication(t *testing.T) {
	key := pbkdf2.Key([]byte("pw"), bytes.Repeat([]byte{0x02}, SaltSize),
		MinIterations, KeySizeBytes, sha256.New)
	aead, err := subtle.NewAESGCMHKDF(key, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF: %v", err)
	}

	var ct bytes.Buffer
	w, _ := aead.NewEncryptingWriter(&ct, []byte(AssociatedData))
	_, _ = w.Write([]byte("payload"))
	_ = w.Close()

	r, err := aead.NewDecryptingReader(bytes.NewReader(ct.Bytes()), []byte("tryst-backup-v2"))
	if err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("decrypted under the wrong associated data — the AD is not being enforced")
		}
	}
}

// A wrong password must fail on authentication, cleanly, with no partial output
// (requirement N7). This is the single most common real-world failure and it
// must not look like corruption.
func TestWrongPasswordFailsCleanly(t *testing.T) {
	salt := bytes.Repeat([]byte{0x03}, SaltSize)
	right := pbkdf2.Key([]byte("right"), salt, MinIterations, KeySizeBytes, sha256.New)
	wrong := pbkdf2.Key([]byte("wrong"), salt, MinIterations, KeySizeBytes, sha256.New)

	encAEAD, _ := subtle.NewAESGCMHKDF(right, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	var ct bytes.Buffer
	w, _ := encAEAD.NewEncryptingWriter(&ct, []byte(AssociatedData))
	_, _ = w.Write([]byte("secret"))
	_ = w.Close()

	decAEAD, _ := subtle.NewAESGCMHKDF(wrong, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	r, err := decAEAD.NewDecryptingReader(bytes.NewReader(ct.Bytes()), []byte(AssociatedData))
	if err == nil {
		out, err := io.ReadAll(r)
		if err == nil {
			t.Fatal("the wrong password decrypted the stream")
		}
		if len(out) != 0 {
			t.Fatalf("wrong password produced %d bytes of partial output; want 0 (N7)", len(out))
		}
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
