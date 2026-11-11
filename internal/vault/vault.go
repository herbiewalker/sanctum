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
// Package vault is Sanctum's top-level coordinator: the LOCKED/UNLOCKED state
// machine and the composition point for blobstore + index + ingest + session.
//
// Every other package is a component; vault is what glues them together in the
// order Sanctum actually needs. The lifecycle is:
//
//	New(paths) → returns a LOCKED vault
//	  ↓
//	Unlock(passphrase) → derives key, unseals index, wires ingest, spins up session mgr
//	  ↓
//	work happens through Ingest() / Sessions() / Store() / Index()
//	  ↓
//	Lock() → re-seals index, zeros the runtime key, clears sessions
//	  ↓
//	Close() → shut down cleanly (calls Lock if still unlocked)
//
// Everything above the state machine assumes IsUnlocked() is true at method
// entry; the http handlers double-check with a shared middleware.
package vault

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/ingest"
	"github.com/herbiewalker/sanctum/internal/session"
	"github.com/herbiewalker/sanctum/internal/vaultkey"
)

// Paths tells Vault where things live. VaultDir AND TmpDir are both
// required — TmpDir MUST resolve to a tmpfs-like mount so that the live
// SQLite index and any transient decrypt buffer never touch the array
// (hard constraint 2). On Linux, New() statfs()es TmpDir and refuses to
// start if it is not tmpfs/ramfs. Off-Linux (or when the operator
// genuinely wants an on-disk tmp for a dev box), set AllowNonTmpfsTmpDir
// to bypass that check.
type Paths struct {
	VaultDir string // holds manifest.json, index.sealed, vault/<owner>/*.tryst
	TmpDir   string // tmpfs — where the live SQLite index materialises while unlocked
	InboxDir string // where the watcher polls; not touched by vault itself

	// AllowNonTmpfsTmpDir bypasses the tmpfs guard on TmpDir. Never set true
	// in a real deployment — this is for tests and dev boxes where the OS
	// or filesystem does not expose the check. Production wiring in
	// cmd/sanctum leaves this false.
	AllowNonTmpfsTmpDir bool
}

// Options let the caller inject clocks and id generators for tests.
type Options struct {
	Now         func() time.Time
	NewBackupID ingest.IDGenerator
	Logger      *slog.Logger
	Session     session.Config // TTLs; zero values use session.DefaultConfig

	// AllowInsecureKDF bypasses the production Argon2id floor check in
	// Unlock. Set only in tests, benchmarks, and dev boxes running with
	// vaultkey.TestParams (which take microseconds instead of the
	// production ~500 ms). Never true in a real deployment — a manifest
	// below the floor is either a tampering signal or a bug (see F03).
	AllowInsecureKDF bool
}

// Well-known errors.
var (
	ErrLocked          = errors.New("vault: locked")
	ErrAlreadyUnlocked = errors.New("vault: already unlocked")
	ErrBadPassphrase   = errors.New("vault: unlock failed — wrong passphrase or corrupted seal")
)

// Vault holds the compositional state.
type Vault struct {
	paths            Paths
	manifest         Manifest
	state            *stateStore
	logger           *slog.Logger
	now              func() time.Time
	newID            ingest.IDGenerator
	sessOpts         session.Config
	allowInsecureKDF bool // F03: bypass ValidateProduction; tests/dev only

	// blobstore is available while LOCKED too — restore-a-file-by-hash
	// remains possible without unlocking. Ingest and index do not.
	store *blobstore.Store

	// Everything below only exists while UNLOCKED.
	mu       sync.RWMutex
	unlocked bool
	key      *vaultkey.Key
	idx      *index.Index
	ing      *ingest.Service
	sessions *session.Manager

	// D01 checkpoint machinery. stopCP is closed (and nilled) by Lock; the
	// checkpoint goroutine of that unlock generation exits when it sees it.
	stopCP  chan struct{}
	nudgeCP chan struct{}
	cpMu    sync.Mutex // guards lastSum and serialises sealing
	lastSum [32]byte   // SHA-256 of the plaintext last written to disk
}

// ErrTmpDirNotTmpfs is returned by New when Paths.TmpDir is on a
// disk-backed filesystem and Paths.AllowNonTmpfsTmpDir is false. Fixing
// this in production means adding a `tmpfs:` mount for the container's
// TmpDir; fixing it for a local dev box means setting the opt-in.
var ErrTmpDirNotTmpfs = errors.New(
	"vault: TmpDir is not on a tmpfs/ramfs mount — decrypted state would " +
		"land on the array (hard constraint 2). Mount a tmpfs there, or " +
		"set Paths.AllowNonTmpfsTmpDir=true if this is a dev box.")

// New constructs a Vault. The vault starts LOCKED. Reads or creates the
// manifest, opens the blob store, and returns; no key derivation until
// Unlock is called.
//
// Both VaultDir and TmpDir are required. TmpDir is verified to be a
// tmpfs-like mount on Linux (statfs → tmpfs/ramfs magic); off-Linux the
// caller must set Paths.AllowNonTmpfsTmpDir explicitly. This is the
// runtime backstop for hard constraint 2 — the no-plaintext guard covers
// CI, this covers production start-up.
func New(paths Paths, opt Options) (*Vault, error) {
	if paths.VaultDir == "" {
		return nil, errors.New("vault: VaultDir is required")
	}
	if paths.TmpDir == "" {
		return nil, errors.New("vault: TmpDir is required")
	}
	if paths.TmpDir == paths.VaultDir {
		// Defence in depth: config.Load enforces this too, but a caller
		// that builds Paths programmatically must not slip past.
		return nil, errors.New("vault: TmpDir must not equal VaultDir")
	}
	if err := os.MkdirAll(paths.TmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: mkdir TmpDir: %w", err)
	}
	if !paths.AllowNonTmpfsTmpDir {
		ok, err := isTmpfsBacked(paths.TmpDir)
		if err != nil {
			return nil, fmt.Errorf("vault: verify TmpDir is tmpfs: %w", err)
		}
		if !ok {
			return nil, ErrTmpDirNotTmpfs
		}
	}

	m, _, err := LoadOrCreateManifest(paths.VaultDir)
	if err != nil {
		return nil, err
	}
	store, err := blobstore.New(filepath.Join(paths.VaultDir, "blobs"))
	if err != nil {
		return nil, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Session.IdleTTL == 0 && opt.Session.MaxTTL == 0 {
		opt.Session = session.DefaultConfig()
	}
	return &Vault{
		paths:            paths,
		manifest:         m,
		state:            newStateStore(paths.VaultDir),
		logger:           opt.Logger,
		now:              opt.Now,
		newID:            opt.NewBackupID,
		sessOpts:         opt.Session,
		allowInsecureKDF: opt.AllowInsecureKDF,
		store:            store,
		nudgeCP:          make(chan struct{}, 1),
	}, nil
}

// State returns the cleartext operational state (locked-since etc).
// Safe to call in any state — the scheduler reads it while the vault is
// locked to decide whether to fire a "locked since X" alert (D-18).
func (v *Vault) State() (State, error) { return v.state.Load() }

// UpdateState mutates state.json atomically. Used by the scheduler to bump
// LastLockedAlertAt after firing.
func (v *Vault) UpdateState(mutate func(*State)) error { return v.state.Update(mutate) }

// IsUnlocked reports the current state. Callers that need to gate on state
// (HTTP middleware) use this.
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.unlocked
}

// Store returns the blob store (always safe to call — the store does not
// need the runtime key to write immutable ciphertext or verify SHAs).
func (v *Vault) Store() *blobstore.Store { return v.store }

// Index, Ingest, Sessions return nil while LOCKED. Callers must gate on
// IsUnlocked() before dereferencing.
func (v *Vault) Index() *index.Index {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.idx
}
func (v *Vault) Ingest() *ingest.Service {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.ing
}
func (v *Vault) Sessions() *session.Manager {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.sessions
}

// Manifest returns the loaded manifest — used by handlers that want to
// display KDF settings for operator diagnostics.
func (v *Vault) Manifest() Manifest { return v.manifest }

// FirstRun reports whether this vault has never been locked, i.e. no sealed index
// exists yet. The unlock page uses it to ask for the passphrase twice, because
// on a brand-new vault whatever is typed becomes the passphrase.
func (v *Vault) FirstRun() bool { return !index.SealExists(v.paths.VaultDir) }

// Unlock derives the runtime key, unseals the index if a seal exists (or
// creates a fresh in-memory index on first run), and wires up ingest and
// sessions. Returns ErrBadPassphrase for any AEAD auth failure.
//
// Idempotent-ish: an already-unlocked vault returns ErrAlreadyUnlocked.
// (Silently succeeding would hide a bug where the caller lost track of
// state; better to fail loudly.)
func (v *Vault) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.unlocked {
		return ErrAlreadyUnlocked
	}

	// F03: refuse to derive under weak params before touching the passphrase.
	// The check is on the manifest as read from disk — an operator who edits
	// it downwards, or a code path that minted TestParams into a real vault
	// by mistake, gets ErrKDFBelowProductionFloor instead of a silently-weak
	// derivation. Opt-out lives on Options.AllowInsecureKDF for tests.
	if !v.allowInsecureKDF {
		if err := vaultkey.ValidateProduction(v.manifest.KDF); err != nil {
			v.logger.Error("vault unlock: manifest KDF below production floor",
				"kdf", v.manifest.KDF.KDF,
				"t", v.manifest.KDF.Time,
				"m_kib", v.manifest.KDF.MemoryKiB,
				"p", v.manifest.KDF.Parallel,
				"err", err.Error())
			return fmt.Errorf("vault: %w", err)
		}
	}

	key, err := vaultkey.Derive(passphrase, v.manifest.KDF)
	if err != nil {
		return fmt.Errorf("vault: derive key: %w", err)
	}
	// Any error from here on must Zero the key — nothing else must ever
	// see the derived bytes if the unlock is going to fail.
	cleanupKey := true
	defer func() {
		if cleanupKey {
			key.Zero()
		}
	}()

	sealDir := v.paths.VaultDir
	idx, err := unsealOrOpen(sealDir, v.paths.TmpDir, key, manifestBinding(v.manifest.KDF))
	if err != nil {
		return err
	}

	ing, err := ingest.New(v.store, idx, ingest.Options{
		TmpDir: v.paths.TmpDir,
		NewID:  v.newID,
		Now:    v.now,
		Logger: v.logger,
		// A new backup is the change that hurts most to lose: seal promptly.
		OnCommit: v.nudgeCheckpoint,
	})
	if err != nil {
		_ = idx.Close()
		return err
	}

	sess, err := session.NewManager(session.ManagerOptions{
		Config: v.sessOpts,
		Now:    v.now,
		Logger: v.logger,
	})
	if err != nil {
		_ = idx.Close()
		return err
	}

	v.key = key
	v.idx = idx
	v.ing = ing
	v.sessions = sess
	v.unlocked = true
	cleanupKey = false // ownership transferred to the Vault
	v.startCheckpointer()

	// Clear LockedSince — the vault is no longer locked. LastLockedAlertAt
	// is left alone: it debounces the next lock cycle too, so a re-lock in
	// quick succession does not double-fire.
	if err := v.state.Update(func(s *State) { s.LockedSince = 0 }); err != nil {
		v.logger.Warn("vault unlock: state update failed", "err", err.Error())
	}
	v.logger.Info("vault unlocked", "seal_dir", sealDir)
	return nil
}

// Lock re-seals the index, zeroes the runtime key, and clears every issued
// session (N17). Idempotent: a Lock on an already-locked vault is a no-op.
//
// If the re-seal fails the runtime key IS STILL ZEROED — the caller loses
// any writes since the last seal, and the operator will see the error and
// know to investigate. We do NOT keep the key alive "for a retry" because
// D-4 says the key never survives a re-lock intent; a partial-fail that
// silently kept the key would violate that.
func (v *Vault) Lock() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.unlocked {
		return nil
	}

	// Stop the checkpoint goroutine (it exits on its own; it never blocks us).
	if v.stopCP != nil {
		close(v.stopCP)
		v.stopCP = nil
	}

	// Ingest first — if a Service call is racing us it will see
	// ErrVaultLocked and back out before we tear down the index it uses.
	if v.ing != nil {
		v.ing.Lock()
	}
	if v.sessions != nil {
		v.sessions.Clear() // N17
	}

	sealErr := sealAndClose(v.idx, v.paths.VaultDir, v.paths.TmpDir,
		v.key.Bytes(), manifestBinding(v.manifest.KDF))

	// Zero the key regardless of seal outcome. See docstring rationale.
	v.key.Zero()
	v.key = nil
	v.idx = nil
	v.ing = nil
	v.sessions = nil
	v.unlocked = false

	// Record the transition timestamp for the locked-since alert path
	// (D-18). This runs even if the re-seal failed — the vault IS locked
	// at this point (key zeroed, unlocked=false), and the scheduler needs
	// an accurate lock time to reason about staleness.
	nowUnix := v.now().Unix()
	if err := v.state.Update(func(s *State) { s.LockedSince = nowUnix }); err != nil {
		v.logger.Warn("vault lock: state update failed", "err", err.Error())
	}

	if sealErr != nil {
		v.logger.Error("vault re-seal failed on Lock", "err", sealErr.Error())
		return fmt.Errorf("vault: re-seal on lock: %w", sealErr)
	}
	v.logger.Info("vault locked")
	return nil
}

// Close shuts the vault down cleanly — Lock if still unlocked, then release
// any remaining handles. Called on SIGTERM (N11).
func (v *Vault) Close() error {
	if v.IsUnlocked() {
		if err := v.Lock(); err != nil {
			return err
		}
	}
	return nil
}

// ErrManifestOutOfBand is returned by Unlock when the seal on disk
// authenticates fine on its own but its manifest binding hash does not
// match the current manifest.json. This distinguishes a wrong-passphrase
// error from a "manifest.json has been swapped, moved, or tampered with"
// error — the operator sees a distinct signal and can investigate.
var ErrManifestOutOfBand = errors.New(
	"vault: manifest.json has changed since this seal was written " +
		"(or the seal was moved between vaults) — see docs/RUNBOOK.md")

// unsealOrOpen returns a live index: unseal from disk if a seal exists,
// otherwise create a fresh in-memory one (first-run vault).
func unsealOrOpen(sealDir, tmpDir string, key *vaultkey.Key, binding []byte) (*index.Index, error) {
	// D02: a fresh index is allowed ONLY when no seal generation of any kind
	// (current, unpromoted tmp, previous) is on disk. If index.sealed is merely
	// missing because a crash hit SealFile between its two renames, the .tmp or
	// .prev file is still there, and the passphrase must authenticate against it.
	if !index.SealExists(sealDir) {
		return index.OpenInMemory()
	}
	sqliteBytes, err := index.UnsealFile(sealDir, key.Bytes(), binding)
	if err != nil {
		if errors.Is(err, index.ErrSealManifestOutOfBand) {
			return nil, ErrManifestOutOfBand
		}
		if errors.Is(err, index.ErrSealAuth) {
			return nil, ErrBadPassphrase
		}
		return nil, fmt.Errorf("vault: unseal: %w", err)
	}
	return index.LoadInto(sqliteBytes, tmpDir)
}

// sealAndClose serialises the live index and writes it back as a new seal.
// The index handle is Closed either way — the caller has already committed
// to a re-lock and does not want the handle to leak.
func sealAndClose(idx *index.Index, sealDir, tmpDir string, keyBytes, binding []byte) error {
	if idx == nil {
		return nil
	}
	raw, err := idx.Serialize(tmpDir)
	if err != nil {
		_ = idx.Close()
		return fmt.Errorf("serialize index: %w", err)
	}
	if err := index.SealFile(sealDir, keyBytes, binding, raw); err != nil {
		_ = idx.Close()
		return fmt.Errorf("SealFile: %w", err)
	}
	// Zero the serialised bytes before letting them go out of scope. Not a
	// guarantee (Go may have made copies internally) but cheap.
	for i := range raw {
		raw[i] = 0
	}
	return idx.Close()
}

func nowUnix() int64 { return time.Now().Unix() }

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
