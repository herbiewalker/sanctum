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
// Package blobstore holds the immutable owner-scoped ciphertext blobs that
// make up a Sanctum vault.
//
// Every stored file is a TRYSTBK1 container as Tryst wrote it — bytes never
// modified, never re-encoded, never re-wrapped (D-11 + N8). This package
// deals ONLY in those opaque bytes plus a SHA-256 manifest sidecar. It never
// decrypts, never parses a header, never touches internal/trystbk — a defect
// here that accidentally opened a blob would violate hard constraint 2 (no
// plaintext to the array) because it would materialise plaintext right next
// to the storage code.
//
// The on-disk layout is defined in docs/DATA_MODEL.md.
package blobstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Well-known errors.
var (
	ErrBlobExists   = errors.New("blobstore: blob already exists (immutable — never rewritten)")
	ErrBlobNotFound = errors.New("blobstore: blob not found")
	ErrHashMismatch = errors.New("blobstore: SHA-256 mismatch — blob tampered or corrupted")
	ErrInvalidID    = errors.New("blobstore: invalid id — must be safe filename")
	ErrInvalidOwner = errors.New("blobstore: invalid owner id")
)

// Store is the file-backed blob store rooted at a single vault directory.
// Safe for concurrent use.
type Store struct {
	root string
	mu   sync.Mutex // serialises writes so ErrBlobExists is deterministic
}

// New opens (creating if needed) the store rooted at vaultRoot. The root
// directory must exist or be creatable. Sub-directories per owner are made
// on demand.
func New(vaultRoot string) (*Store, error) {
	if vaultRoot == "" {
		return nil, errors.New("blobstore: empty root")
	}
	if err := os.MkdirAll(vaultRoot, 0o755); err != nil {
		return nil, fmt.Errorf("blobstore: mkdir %q: %w", vaultRoot, err)
	}
	return &Store{root: vaultRoot}, nil
}

// Root returns the vault root directory. Used by manifest.json handling and
// by tests that want to scan the layout.
func (s *Store) Root() string { return s.root }

// Put writes ciphertext under (ownerID, id) atomically and returns its SHA-256.
//
// The write goes to a `.tmp` sibling first and is renamed on success; a
// crashed process therefore never leaves a partial blob visible to a later
// reader. The sidecar manifest is written after the blob and is the single
// source of truth for verification (Get compares against it).
//
// Attempting to Put a blob that already exists returns ErrBlobExists — blobs
// are immutable by design (D-11). Callers who need duplicate detection should
// check the SHA-256 against the index (F13); this API does not silently
// overwrite.
func (s *Store) Put(ownerID, id string, ciphertext io.Reader) ([]byte, error) {
	if err := validateOwnerID(ownerID); err != nil {
		return nil, err
	}
	if err := validateID(id); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerDir := filepath.Join(s.root, ownerID)
	if err := os.MkdirAll(ownerDir, 0o755); err != nil {
		return nil, fmt.Errorf("blobstore: mkdir owner: %w", err)
	}
	final := filepath.Join(ownerDir, id+blobExt)
	sidecar := final + sha256Ext

	if _, err := os.Stat(final); err == nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrBlobExists, ownerID, id)
	}

	tmp, err := os.CreateTemp(ownerDir, "."+id+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("blobstore: create tmp: %w", err)
	}
	// Any early-exit must remove the tmp; the deferred cleanup below is a
	// belt for the case where success skips the explicit Remove.
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), ciphertext); err != nil {
		return nil, fmt.Errorf("blobstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("blobstore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("blobstore: close tmp: %w", err)
	}

	sum := h.Sum(nil)

	// Sidecar first? No — the blob is what matters. Write it, then the
	// sidecar. If a crash lands between the two, Verify catches it (missing
	// sidecar) rather than silently returning wrong data.
	if err := os.Rename(tmpPath, final); err != nil {
		return nil, fmt.Errorf("blobstore: rename: %w", err)
	}
	cleanup = false

	if err := os.WriteFile(sidecar, []byte(hex.EncodeToString(sum)+"\n"), 0o644); err != nil {
		// Best effort: leave the blob (immutable — do NOT delete it), and
		// surface the error. The next Verify will notice the missing sidecar
		// and can rewrite it from a re-hash.
		return nil, fmt.Errorf("blobstore: write sidecar: %w", err)
	}
	return sum, nil
}

// Get returns a reader for the blob's bytes and its declared SHA-256.
//
// The returned reader hashes as bytes flow through it; the caller MUST call
// Close for the hash comparison to run. A ReadCloser that is dropped without
// Close returns whatever bytes were read but performs no verification —
// callers that skip Close are opting out of D-11.
func (s *Store) Get(ownerID, id string) (*Reader, error) {
	if err := validateOwnerID(ownerID); err != nil {
		return nil, err
	}
	if err := validateID(id); err != nil {
		return nil, err
	}
	final := filepath.Join(s.root, ownerID, id+blobExt)
	sidecar := final + sha256Ext

	declared, err := readSidecar(sidecar)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(final)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s/%s", ErrBlobNotFound, ownerID, id)
		}
		return nil, err
	}

	return &Reader{
		f:        f,
		hash:     sha256.New(),
		declared: declared,
	}, nil
}

// Verify re-hashes the blob end-to-end and confirms it matches the sidecar.
// This is the periodic re-check that F15 uses; the on-read verify in Get
// gives us the same guarantee when the blob is actually consumed.
func (s *Store) Verify(ownerID, id string) error {
	r, err := s.Get(ownerID, id)
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	return r.Close()
}

// Delete removes a blob and its sidecar. Only retention (M5) calls this —
// blobs are immutable for the life of the vault (D-11), and pruning is the
// single sanctioned deletion path. The order is sidecar-first: if the blob
// removal fails, a later Get sees "missing sidecar" and refuses to serve
// bytes, which is the honest error.
//
// Missing files are not an error — Delete is idempotent so a retry after a
// partial failure converges.
func (s *Store) Delete(ownerID, id string) error {
	if err := validateOwnerID(ownerID); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	final := filepath.Join(s.root, ownerID, id+blobExt)
	sidecar := final + sha256Ext

	if err := os.Remove(sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blobstore: remove sidecar: %w", err)
	}
	if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blobstore: remove blob: %w", err)
	}
	return nil
}

// Entry is a listing element for a single blob.
type Entry struct {
	ID     string
	SHA256 []byte
	Size   int64
}

// List returns all blobs for one owner. Order is filesystem-dependent; the
// caller sorts as needed (typically by ingested_at from the index).
func (s *Store) List(ownerID string) ([]Entry, error) {
	if err := validateOwnerID(ownerID); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.root, ownerID)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // empty owner is not an error
		}
		return nil, err
	}
	var out []Entry
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, blobExt) {
			continue
		}
		id := strings.TrimSuffix(name, blobExt)
		if err := validateID(id); err != nil {
			continue // ignore anything that isn't a legal blob id
		}
		full := filepath.Join(dir, name)
		info, err := os.Stat(full)
		if err != nil {
			return nil, err
		}
		sum, err := readSidecar(full + sha256Ext)
		if err != nil {
			// A blob without its sidecar is a corruption we surface, not hide.
			return nil, fmt.Errorf("blobstore: missing sidecar for %s/%s: %w", ownerID, id, err)
		}
		out = append(out, Entry{ID: id, SHA256: sum, Size: info.Size()})
	}
	return out, nil
}

// ListOwners enumerates owner directories, used by rebuild-from-blobs (F12).
func (s *Store) ListOwners() ([]string, error) {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue // skip .tmp dirs, hidden dirs
		}
		if validateOwnerID(name) != nil {
			continue // not a valid owner id
		}
		out = append(out, name)
	}
	return out, nil
}

// Reader wraps an *os.File and a running hash; Close performs the verify.
type Reader struct {
	f    *os.File
	hash interface {
		io.Writer
		Sum([]byte) []byte
	}
	declared []byte
	closed   bool
	err      error
}

// Read forwards bytes and feeds the running SHA-256.
func (r *Reader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	n, err := r.f.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	return n, err
}

// Close finalises the hash comparison and closes the underlying file.
// Returns ErrHashMismatch if the bytes read did not match the sidecar.
//
// If Read stopped early (e.g. the caller only wanted the first megabyte),
// Close will still hash only what was actually read, and the mismatch will
// fire — this is the correct behaviour, because a partial read is not a
// verified read.
func (r *Reader) Close() error {
	if r.closed {
		return r.err
	}
	r.closed = true
	sum := r.hash.Sum(nil)
	closeErr := r.f.Close()
	if !equalHash(sum, r.declared) {
		r.err = fmt.Errorf("%w: got %s, want %s",
			ErrHashMismatch, hex.EncodeToString(sum), hex.EncodeToString(r.declared))
		return r.err
	}
	r.err = closeErr
	return closeErr
}

// --- private helpers --------------------------------------------------------

const (
	blobExt   = ".tryst"
	sha256Ext = ".sha256"
)

// validateID rejects anything that could break out of the owner dir. IDs are
// generated by Sanctum (ULIDs); this validator is defence in depth for the
// case where a future code path takes an id from an untrusted source.
func validateID(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("%w: %q (illegal char %q)", ErrInvalidID, id, r)
		}
	}
	return nil
}

func validateOwnerID(id string) error {
	if err := validateID(id); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOwner, err)
	}
	return nil
}

func readSidecar(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) != sha256.Size*2 {
		return nil, fmt.Errorf("blobstore: sidecar %q malformed (len=%d)", path, len(trimmed))
	}
	sum, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("blobstore: sidecar %q: %w", path, err)
	}
	return sum, nil
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// Constant-time compare — not strictly necessary for a locally-stored
	// hash but the cost is nothing.
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
