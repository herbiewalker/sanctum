package index

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Seal / unseal — the D-5 hand-off between the tmpfs-only live index and the
// array-resident encrypted blob.
//
// The primitive is AES-256-GCM (single-shot, not streaming): the index is
// small (bounded by real user metadata at the order of hundreds of KiB, and
// well under any sane cap even for a large user), and streaming buys nothing
// here while adding complexity. The runtime key is the 32-byte output of
// vaultkey.Derive (Argon2id, D-16).
//
// Wire format (raw bytes on disk):
//
//	magic     4 bytes  "SNSL"        // "seal" — distinguishes from a raw SQLite file
//	version   1 byte   0x01          // for future format evolution
//	reserved  3 bytes  0x00 0x00 0x00
//	nonce     12 bytes random per seal
//	ciphertext + tag  variable       // GCM output over the SQLite bytes
//
// A wrong runtime key fails on tag verification, cleanly, with no partial
// output — the mirror of TRYSTBK1's own "wrong password fails cleanly"
// property (N7).

// Wire format v2 (F05): the header carries a SHA-256 of the caller-supplied
// "binding" — Sanctum uses the manifest KDF bytes here so a tampered
// manifest.json produces ErrSealManifestOutOfBand *before* the AEAD attempt
// runs. The binding hash is also inside the AAD, so an attacker who rewrote
// the header hash to match a tampered manifest would still fail GCM auth.
//
//	magic       4 bytes  "SNSL"
//	version     1 byte   0x02
//	reserved    3 bytes  0x00 0x00 0x00
//	bindHash   32 bytes  SHA-256 of the caller-supplied binding blob
//	nonce      12 bytes  random per seal
//	ciphertext + tag     variable  (AAD = header bytes minus nonce, i.e. first 40)
//
// v1 seals (no bindHash, hdrLen=20) are rejected with ErrSealBadVersion.
// Sanctum is pre-M6; there is no live seal on the array to migrate.
const (
	sealMagic    = "SNSL"
	sealVersion  = byte(2)
	bindHashLen  = 32
	sealHdrLen   = len(sealMagic) + 1 + 3 + bindHashLen + 12 // 52 bytes
	nonceLen     = 12
	sealFileName = "index.sealed"
	prevFileName = "index.sealed.prev"
	tmpFileName  = "index.sealed.tmp"
)

// Well-known seal errors.
var (
	ErrSealBadMagic          = errors.New("index/seal: bad magic — file is not a Sanctum seal")
	ErrSealBadVersion        = errors.New("index/seal: unsupported seal format version")
	ErrSealTruncated         = errors.New("index/seal: file too short to be a valid seal")
	ErrSealAuth              = errors.New("index/seal: unseal failed — wrong key or tampered seal")
	ErrSealManifestOutOfBand = errors.New(
		"index/seal: manifest binding hash mismatch — manifest.json has changed " +
			"since this seal was written (or the seal was moved between vaults)")
)

// SealBytes encrypts the raw SQLite bytes under runtimeKey and returns the
// wire form. Nonce is fresh per call; never reuse a nonce with the same key.
//
// binding is the caller-supplied blob whose SHA-256 gets stored in the header
// and bound into GCM AAD (F05). Sanctum's vault layer passes the canonical
// bytes of the manifest KDF stanza; nil is legal (empty binding) but only
// tests use it — real callers should always thread a real binding through so
// a tampered manifest surfaces as ErrSealManifestOutOfBand at unseal.
func SealBytes(runtimeKey, binding, plaintext []byte) ([]byte, error) {
	if len(runtimeKey) != 32 {
		return nil, fmt.Errorf("index/seal: runtime key must be 32 bytes, got %d", len(runtimeKey))
	}
	block, err := aes.NewCipher(runtimeKey)
	if err != nil {
		return nil, fmt.Errorf("index/seal: AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("index/seal: GCM: %w", err)
	}

	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("index/seal: nonce: %w", err)
	}

	bindHash := sha256.Sum256(binding)

	out := make([]byte, 0, sealHdrLen+len(plaintext)+gcm.Overhead())
	out = append(out, []byte(sealMagic)...)
	out = append(out, sealVersion)
	out = append(out, 0, 0, 0)
	out = append(out, bindHash[:]...)
	out = append(out, nonce[:]...)
	// AAD covers everything the header authenticates, minus the nonce (the
	// nonce is passed separately to GCM). Tampering with any of
	// magic/version/reserved/bindHash therefore fails GCM auth even if the
	// pre-check somehow accepted a swapped hash.
	out = gcm.Seal(out, nonce[:], plaintext, out[:sealHdrLen-nonceLen])
	return out, nil
}

// UnsealBytes reverses SealBytes. Two distinct failure modes are returned:
//
//   - ErrSealManifestOutOfBand — the header bindHash does not match SHA-256
//     of the caller-supplied binding. Surfaced BEFORE the AEAD attempt so
//     the operator can see "the manifest has drifted" as a separate signal
//     from "wrong passphrase".
//   - ErrSealAuth — the AEAD tag failed. By design the AEAD cannot
//     distinguish "wrong key" from "tampered ciphertext"; both funnel here.
func UnsealBytes(runtimeKey, binding, sealed []byte) ([]byte, error) {
	if len(sealed) < sealHdrLen {
		return nil, ErrSealTruncated
	}
	if string(sealed[:4]) != sealMagic {
		return nil, ErrSealBadMagic
	}
	if sealed[4] != sealVersion {
		return nil, fmt.Errorf("%w: %d (this build handles version %d)",
			ErrSealBadVersion, sealed[4], sealVersion)
	}
	if len(runtimeKey) != 32 {
		return nil, fmt.Errorf("index/seal: runtime key must be 32 bytes, got %d", len(runtimeKey))
	}

	storedHash := sealed[8 : 8+bindHashLen]
	expectHash := sha256.Sum256(binding)
	if subtle.ConstantTimeCompare(storedHash, expectHash[:]) != 1 {
		return nil, ErrSealManifestOutOfBand
	}

	nonce := sealed[8+bindHashLen : 8+bindHashLen+nonceLen]
	ct := sealed[sealHdrLen:]
	aad := sealed[:sealHdrLen-nonceLen] // magic + version + reserved + bindHash

	block, err := aes.NewCipher(runtimeKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrSealAuth, err)
	}
	return pt, nil
}

// SealFile writes the sealed bytes to <dir>/index.sealed atomically, keeping
// the previous seal as <dir>/index.sealed.prev. A crash mid-write leaves the
// previous seal intact — a failed seal must never destroy the last good one.
//
// binding is the F05 manifest-binding blob; see SealBytes.
func SealFile(dir string, runtimeKey, binding, plaintext []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sealed, err := SealBytes(runtimeKey, binding, plaintext)
	if err != nil {
		return err
	}

	sealPath := filepath.Join(dir, sealFileName)
	prevPath := filepath.Join(dir, prevFileName)
	tmpPath := filepath.Join(dir, tmpFileName)

	if err := writeFileAtomic(tmpPath, sealed, 0o600); err != nil {
		return err
	}
	// Promote the current seal to .prev BEFORE moving tmp into place. If we
	// crash between these two steps, UnsealFile recovers from the tmp file
	// (see its doc comment) — that is why writeFileAtomic already fsync'd it.
	if _, err := os.Stat(sealPath); err == nil {
		// Best-effort rename to .prev. If it fails we still try to promote
		// tmp — the caller sees the error and can retry.
		if err := os.Rename(sealPath, prevPath); err != nil {
			return fmt.Errorf("promote to .prev: %w", err)
		}
	}
	if err := os.Rename(tmpPath, sealPath); err != nil {
		return fmt.Errorf("promote tmp: %w", err)
	}
	return nil
}

// UnsealFile returns the plaintext of the newest seal generation that
// authenticates under runtimeKey. Candidates, newest first:
//
//  1. <dir>/index.sealed      the current seal
//  2. <dir>/index.sealed.tmp  a complete new seal that a crash left unpromoted.
//     SealFile only renames the old seal away AFTER this file is written and
//     fsync'd, so when index.sealed is missing this one is the newest.
//     (AEAD authentication rejects it if the crash cut the write short.)
//  3. <dir>/index.sealed.prev the previous generation (D-5)
//
// Missing files are skipped. If no candidate exists at all the error wraps
// os.ErrNotExist; callers must treat "nothing exists" as a first run ONLY
// after checking SealExists, never on any other failure (D02: a failed or
// unauthenticated seal must never be treated as a fresh vault).
//
// Error precedence: if any candidate existed but did not authenticate, that
// auth error is returned (wrong key is more actionable than "not found").
//
// F05 special case: ErrSealManifestOutOfBand short-circuits the fallbacks —
// every generation was written under the same manifest, so if one binding
// fails the others will too.
func UnsealFile(dir string, runtimeKey, binding []byte) ([]byte, error) {
	var authErr, readErr error
	for _, name := range []string{sealFileName, tmpFileName, prevFileName} {
		sealed, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if readErr == nil {
				readErr = err
			}
			continue
		}
		pt, err := UnsealBytes(runtimeKey, binding, sealed)
		if err == nil {
			return pt, nil
		}
		if errors.Is(err, ErrSealManifestOutOfBand) {
			return nil, err
		}
		if authErr == nil {
			authErr = err
		}
	}
	if authErr != nil {
		return nil, authErr
	}
	return nil, readErr
}

// writeFileAtomic is a small helper: write to tmp, fsync, rename. The
// blobstore has its own tmp-and-rename; using a shared implementation here
// would drag it into an internal dependency cycle.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Serialize writes the current index to a byte slice by dumping it to a
// temporary path and reading it back. modernc.org/sqlite exposes a Backup API
// on connections that would let us do this in memory, but the .Backup path
// is driver-specific and this method keeps the seal layer driver-agnostic.
//
// The temporary path MUST live on tmpfs (constraint 2) — the caller supplies
// the directory. Serialize deletes the temp file before returning.
func (i *Index) Serialize(tmpDir string) ([]byte, error) {
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, fmt.Errorf("index: mkdir tmp: %w", err)
	}
	tmp, err := os.CreateTemp(tmpDir, "index.*.tmp.sqlite")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close() // sqlite will reopen it
	defer os.Remove(tmpPath)

	// VACUUM INTO writes a fresh compact copy of the in-memory DB to the
	// given path. Uses standard SQL; portable across drivers.
	if _, err := i.db.Exec(fmt.Sprintf("VACUUM INTO %s", quoteSQLLiteral(tmpPath))); err != nil {
		return nil, fmt.Errorf("index: VACUUM INTO: %w", err)
	}
	return os.ReadFile(tmpPath)
}

// LoadInto restores the given SQLite bytes into a fresh in-memory index.
// This is the inverse of Serialize + Seal — the pair used at unlock time.
func LoadInto(sqliteBytes []byte, tmpDir string) (*Index, error) {
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(tmpDir, "loaded.*.sqlite")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(sqliteBytes); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	// Note: we intentionally do NOT delete tmpPath here — the SQLite handle
	// keeps it open. The caller's tmpDir is expected to be tmpfs and to be
	// wiped on container restart.
	return OpenFile(tmpPath)
}

// quoteSQLLiteral escapes a path for use inside a VACUUM INTO ... quoted
// literal. Delimits with a single-quote so backslashes and slashes on
// Windows do not need escaping; embedded single-quotes are doubled per SQL.
func quoteSQLLiteral(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
		} else {
			out = append(out, s[i])
		}
	}
	out = append(out, '\'')
	return string(out)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣

// SealExists reports whether any seal generation (current, unpromoted tmp, or previous) is on disk in
// dir. False means this is a brand-new vault that has never been locked.
func SealExists(dir string) bool {
	for _, name := range []string{sealFileName, tmpFileName, prevFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}
