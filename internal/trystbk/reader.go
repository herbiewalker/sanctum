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
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// Manifest is what Sanctum extracts from a TRYSTBK1 file for the index.
//
// It is DELIBERATELY small. Everything here is either format metadata (version,
// iteration count) or a COUNT — never a value from an encounter row, a partner
// name, a note, a photo byte. That is what makes it safe to write into the
// index (DATA_MODEL "counts, never content").
type Manifest struct {
	Header

	// TrystSchemaVersion is data.json's schemaVersion. Tryst is on v15 at time
	// of writing; a backup from a newer Tryst may have a higher number, and
	// Sanctum stores that verbatim without complaint — a vault that refuses
	// to hold a newer backup has failed at its one job (DATA_MODEL).
	TrystSchemaVersion int

	// TableCounts maps a table name in data.json to its row count. The
	// synthetic key SyntheticMediaKey ("__media__") holds the media entry
	// count — see MediaBytes for its total size (D-15).
	TableCounts map[string]int

	// MediaBytes is the sum of uncompressed sizes of media/* ZIP entries, read
	// from the central directory. Not "seen", not "verified" — declared. The
	// AEAD authenticates the stream, so a declared size that lied would have
	// failed authentication upstream.
	MediaBytes int64

	// ContentSHA256 is the SHA-256 of the ORIGINAL FILE BYTES (from the outer
	// stream's start, including the header). Populated when Open received a
	// reader that let us hash while we consumed — otherwise nil, and the
	// caller (M2 blobstore) hashes independently.
	ContentSHA256 []byte
}

// SyntheticMediaKey is the reserved TableCounts key for the media-directory
// count (D-15). Chosen to be a name that could never appear in Tryst's own
// tables — data.json's tables map keys directly to SQLite table names, which
// cannot start with an underscore-underscore in any Tryst schema.
const SyntheticMediaKey = "__media__"

// Well-known errors from the reader path. Ingest matches on these to decide
// what to log (wrong password is common, oversize is suspicious).
var (
	ErrWrongPassword = errors.New("trystbk: decryption failed — wrong password or tampered stream")
	ErrOversize      = errors.New("trystbk: decrypted body exceeds MaxBackupBytes")
)

// Open reads the header, derives the key from password, decrypts the AEAD
// stream into memory (bounded by MaxBackupBytes), and inspects the inner ZIP.
//
// The decrypted plaintext lives in memory for the duration of this call and
// nowhere else — no tmpfs file is created, no filesystem is touched. On
// return, the buffer goes out of scope; the Go runtime will reclaim it, and
// nothing else in the process ever held a reference. This is what makes
// constraint 2 hold: plaintext exists only in memory, for the life of a
// request.
//
// Open does NOT compute a hash of the ORIGINAL file — the caller (ingest, M2)
// does that once against the raw file, so restore can return byte-identical
// bytes (N8). Hashing here would only hash the header + ciphertext we saw,
// and would drift from what ends up on disk.
func Open(r io.Reader, password string) (*Manifest, error) {
	h, err := ParseHeader(r)
	if err != nil {
		return nil, err
	}
	return openWithHeader(r, h, password)
}

// openWithHeader is the seam ingest will use when it wants to inspect the
// header cheaply (magic + version + iteration bounds) before committing to
// the expensive KDF + decrypt. Kept unexported until M3 has a real use.
func openWithHeader(r io.Reader, h Header, password string) (*Manifest, error) {
	// PBKDF2 is deliberately expensive — with 600k SHA-256 iterations this
	// takes on the order of 100ms per attempt on a modest CPU. That cost is
	// per-password on a per-file basis; ingest's password-set walk (D-13/F18)
	// pays it once per password tried.
	key := pbkdf2.Key([]byte(password), h.Salt[:], h.Iterations, KeySizeBytes, sha256.New)

	aead, err := subtle.NewAESGCMHKDF(key, HKDFAlg, KeySizeBytes, SegmentSize, FirstSegmentOffset)
	if err != nil {
		// Impossible with fixed parameters — but if it ever changes, the
		// wrapping error carries which parameter went wrong.
		return nil, fmt.Errorf("trystbk: build AEAD: %w", err)
	}

	dec, err := aead.NewDecryptingReader(r, []byte(AssociatedData))
	if err != nil {
		return nil, wrapDecryptErr(err)
	}

	// Bound the decrypted body. LimitReader returns EOF after N bytes; if the
	// stream actually had more, io.Copy stops there and the ZIP reader will
	// notice a truncated central directory. To distinguish "we bounded it" we
	// probe for one extra byte after the copy.
	var body bytes.Buffer
	body.Grow(1 << 20) // one segment; avoids the small-buffer allocations
	if _, err := io.Copy(&body, io.LimitReader(dec, MaxBackupBytes)); err != nil {
		return nil, wrapDecryptErr(err)
	}
	// One-byte overflow probe. A legitimate backup ends exactly at EOF; a
	// backup that hit our cap has more bytes waiting. This is the only place
	// we ever call Read on the decrypting stream past MaxBackupBytes.
	var overflow [1]byte
	if n, _ := dec.Read(overflow[:]); n > 0 {
		return nil, fmt.Errorf("%w: %d MiB", ErrOversize, MaxBackupBytes>>20)
	}

	m, err := inspectZip(body.Bytes())
	if err != nil {
		return nil, err
	}
	m.Header = h
	return m, nil
}

// wrapDecryptErr classifies AEAD failures. tink-go returns opaque errors on
// authentication failure; from the caller's perspective they are all "this
// ciphertext did not decrypt under this key," which in practice means the
// password is wrong (the far more common case) OR the stream was tampered
// with. Sanctum cannot tell those apart — the AEAD by design does not — and
// treats both as ErrWrongPassword so callers do not build recovery UX on a
// distinction that does not exist.
func wrapDecryptErr(err error) error {
	if err == nil {
		return nil
	}
	// Preserve io errors that mean "input ended early", to distinguish
	// truncation from tampering in logs. Everything else is grouped.
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("trystbk: stream truncated: %w", err)
	}
	return fmt.Errorf("%w (%v)", ErrWrongPassword, err)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
