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
// Package vaultkey derives Sanctum's runtime key from the operator's
// passphrase and holds it in memory only.
//
// This is the material that unseals the SQLite index (D-5) and, transitively,
// opens every stored backup password (D-13). It exists as a Go value for the
// lifetime of a single UNLOCKED period; a re-lock, a SIGTERM, or a container
// restart destroys it and cannot recover it (D-4).
//
// ADR D-16 (see docs/DECISIONS.md) chooses **Argon2id** for this KDF, not
// PBKDF2. The vault-unlock threat model is exactly what Argon2id was designed
// for: an offline attacker holding the sealed blob has unbounded time and
// unbounded parallelism, and memory-hard KDFs are the only defence that
// meaningfully raises the cost of massively-parallel guessing. Owner-login
// stays PBKDF2 (D-14) because its threat model is different — it protects
// against an online attacker on an active service, not against offline
// analysis of stolen material.
package vaultkey

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KeySize is the runtime key length in bytes (AES-256).
const KeySize = 32

// SaltSize is the KDF salt length. 16 bytes is the Argon2id recommendation.
const SaltSize = 16

// Well-known KDF identifiers persisted in the vault manifest. Using a string
// tag lets a future ADR add a second KDF (e.g. "argon2id-v2" with different
// defaults, or a hypothetical successor) without a schema break — Params
// carries what it needs to re-derive.
const (
	KDFArgon2id = "argon2id"
)

// Params carries everything needed to re-derive a key from a passphrase.
// Persisted in the vault manifest (cleartext, per DATA_MODEL — no secrets).
//
// Every field is validated by Derive; Params written by an older Sanctum
// version must remain re-derivable by newer versions forever, so any change
// here is a manifest schema decision, not a private tweak.
type Params struct {
	KDF        string `json:"kdf"`
	Time       uint32 `json:"t"`        // Argon2id time cost (iterations)
	MemoryKiB  uint32 `json:"m_kib"`    // Argon2id memory cost, in KiB
	Parallel   uint8  `json:"p"`        // Argon2id parallelism (lanes)
	Salt       []byte `json:"salt"`     // random per vault
	KeyLenBits uint32 `json:"key_bits"` // must equal KeySize*8; guarded on read
}

// DefaultParams returns production Argon2id parameters.
//
// Chosen from OWASP's 2023 guidance for memory-hard defense against offline
// attack: t=3, m=64 MiB, p=4. On a modest CPU this takes on the order of
// 500 ms, which is fine for an unlock that happens once per container start
// (D-4) and is far outside what a mass-guessing attacker can afford at scale.
//
// Salt is generated fresh; the caller must persist Params (including Salt)
// alongside the sealed index so re-unlock derives the same key.
func DefaultParams() (Params, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return Params{}, fmt.Errorf("vaultkey: rand: %w", err)
	}
	return Params{
		KDF:        KDFArgon2id,
		Time:       3,
		MemoryKiB:  64 * 1024,
		Parallel:   4,
		Salt:       salt,
		KeyLenBits: KeySize * 8,
	}, nil
}

// TestParams returns fast, insecure parameters for tests. Never used outside
// of tests — the name is a load-bearing hint, and the guard in Derive rejects
// production callers that pass these values by mistake (see IsInsecureForTest).
//
// t=1, m=8 KiB, p=1 — completes in microseconds so the test suite can unlock
// hundreds of times without blowing its budget.
func TestParams() Params {
	salt := make([]byte, SaltSize)
	// Deterministic salt for tests is fine — the whole Params object is
	// insecure-by-design and marked as such.
	for i := range salt {
		salt[i] = byte(i)
	}
	return Params{
		KDF:        KDFArgon2id,
		Time:       1,
		MemoryKiB:  8,
		Parallel:   1,
		Salt:       salt,
		KeyLenBits: KeySize * 8,
	}
}

// IsInsecureForTest returns true if p is at or below TestParams()'s cost.
// Intended for detection in test tooling ("did somebody accidentally wire
// a test-shape Params through a real path?"). NOT the production floor —
// see ValidateProduction for that. This predicate only trips at extreme
// values (t≤1 AND m≤64 KiB AND p≤1); a manifest set to, say, t=2,
// m=1024 would slip past despite being trivially crackable.
func IsInsecureForTest(p Params) bool {
	return p.Time <= 1 && p.MemoryKiB <= 64 && p.Parallel <= 1
}

// ProductionFloor is the minimum Argon2id cost a production Sanctum will
// accept in a manifest. Chosen at OWASP 2023 memory-hard defaults: t=3,
// m=64 MiB, p=1. Below any of these, an offline attacker's guess rate
// gets fast enough that the vault's other defences do not matter.
//
// DefaultParams() must always satisfy this floor — enforced by
// TestDefaultParams_MeetsProductionFloor.
const (
	MinProductionTime      uint32 = 3
	MinProductionMemoryKiB uint32 = 64 * 1024
	MinProductionParallel  uint8  = 1
)

// Well-known errors from Derive / ValidateProduction.
var (
	ErrUnknownKDF              = errors.New("vaultkey: unknown KDF")
	ErrBadKeyLen               = errors.New("vaultkey: KeyLenBits must be 256")
	ErrShortSalt               = errors.New("vaultkey: salt too short")
	ErrEmptyPassphrase         = errors.New("vaultkey: empty passphrase")
	ErrKDFBelowProductionFloor = errors.New("vaultkey: KDF params below production floor")
)

// ValidateProduction returns nil if p meets the production Argon2id floor.
// Sanctum's Vault.Unlock calls this before Derive on every unlock; a
// deployment that wants to run with weaker params (test suite, benchmark,
// dev box) must set Options.AllowInsecureKDF=true.
//
// The check is on the recorded manifest — an operator who edits
// manifest.json downwards, or a code path that mints TestParams into a
// real vault by mistake, gets a loud error instead of a silently-weak
// derivation.
func ValidateProduction(p Params) error {
	if p.KDF != KDFArgon2id {
		return fmt.Errorf("%w: %q", ErrUnknownKDF, p.KDF)
	}
	if p.Time < MinProductionTime {
		return fmt.Errorf("%w: t=%d < %d", ErrKDFBelowProductionFloor, p.Time, MinProductionTime)
	}
	if p.MemoryKiB < MinProductionMemoryKiB {
		return fmt.Errorf("%w: m=%d KiB < %d KiB",
			ErrKDFBelowProductionFloor, p.MemoryKiB, MinProductionMemoryKiB)
	}
	if p.Parallel < MinProductionParallel {
		return fmt.Errorf("%w: p=%d < %d", ErrKDFBelowProductionFloor, p.Parallel, MinProductionParallel)
	}
	return nil
}

// Key holds the runtime key. It is a value type deliberately: it has no
// pointer identity across Zero()/Derive() cycles.
type Key struct {
	bytes [KeySize]byte
	live  bool
}

// Bytes returns a FRESH COPY of the key material — safe to retain across
// a Zero() call (the copy is independent) though there is no reason to.
// Panics on a zeroed key; use-after-lock is a program bug, not something
// to hide behind a returned nil.
//
// F07 note: this used to return an aliasing slice into the Key's storage,
// which meant a caller who squirrelled the slice past Zero() would see
// their bytes silently wiped. The 32-byte copy is trivial next to the
// AES/GCM or Argon2id work that follows and removes the footgun. Callers
// that genuinely need the aliasing behaviour (there are none today) can
// call BytesUnsafe below.
func (k *Key) Bytes() []byte {
	if !k.live {
		panic("vaultkey: Bytes() on a zeroed key")
	}
	out := make([]byte, KeySize)
	copy(out, k.bytes[:])
	return out
}

// BytesUnsafe returns the internal storage without copying. Only exists
// for hot paths where the 32-byte allocation is measurably too expensive
// AND the caller can prove synchronous use before the next Zero(). None
// of Sanctum's production callers meet either bar; prefer Bytes().
func (k *Key) BytesUnsafe() []byte {
	if !k.live {
		panic("vaultkey: BytesUnsafe() on a zeroed key")
	}
	return k.bytes[:]
}

// Zero wipes the key material and marks the Key as dead. Idempotent; safe to
// call on an already-zeroed key. Called on SIGTERM (N11) and on any explicit
// re-lock. After Zero() a call to Bytes() panics — see the docstring.
//
// This is best-effort against a hot attacker with process-memory access — Go
// gives no guarantee that the compiler will not have kept a copy of the value
// in a register or a spilled stack slot. But the primary threat model is a
// crash dump / core file, and a zeroed backing array is enough for that.
func (k *Key) Zero() {
	for i := range k.bytes {
		k.bytes[i] = 0
	}
	k.live = false
}

// Derive runs Argon2id against passphrase and returns a live Key.
func Derive(passphrase string, p Params) (*Key, error) {
	if p.KDF != KDFArgon2id {
		return nil, fmt.Errorf("%w: %q (only %q supported)", ErrUnknownKDF, p.KDF, KDFArgon2id)
	}
	if p.KeyLenBits != KeySize*8 {
		return nil, fmt.Errorf("%w: got %d", ErrBadKeyLen, p.KeyLenBits)
	}
	if len(p.Salt) < 8 {
		return nil, fmt.Errorf("%w: %d bytes (need >= 8)", ErrShortSalt, len(p.Salt))
	}
	if passphrase == "" {
		return nil, ErrEmptyPassphrase
	}

	out := argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.MemoryKiB, p.Parallel, KeySize)
	if len(out) != KeySize {
		// argon2.IDKey returns keyLen bytes by contract; guard belt-and-braces.
		return nil, fmt.Errorf("vaultkey: argon2 returned %d bytes, want %d", len(out), KeySize)
	}

	k := &Key{live: true}
	copy(k.bytes[:], out)
	// Zero the argon2 return slice; nothing the caller can do here changes the
	// fact that the argon2 lib may have made intermediate copies internally.
	for i := range out {
		out[i] = 0
	}
	return k, nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
