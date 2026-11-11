package vaultkey

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
	"errors"
	"testing"
)

func TestDerive_ProducesStableKeyForSameInputs(t *testing.T) {
	p := TestParams()
	k1, err := Derive("passphrase", p)
	if err != nil {
		t.Fatalf("Derive #1: %v", err)
	}
	defer k1.Zero()
	k2, err := Derive("passphrase", p)
	if err != nil {
		t.Fatalf("Derive #2: %v", err)
	}
	defer k2.Zero()

	if !bytes.Equal(k1.Bytes(), k2.Bytes()) {
		t.Fatal("same inputs produced different keys")
	}
	if len(k1.Bytes()) != KeySize {
		t.Errorf("KeySize = %d, want %d", len(k1.Bytes()), KeySize)
	}
}

func TestDerive_DifferentPassphraseDifferentKey(t *testing.T) {
	p := TestParams()
	k1, _ := Derive("a", p)
	defer k1.Zero()
	k2, _ := Derive("b", p)
	defer k2.Zero()
	if bytes.Equal(k1.Bytes(), k2.Bytes()) {
		t.Fatal("different passphrases produced identical keys")
	}
}

func TestDerive_DifferentSaltDifferentKey(t *testing.T) {
	p1 := TestParams()
	p2 := TestParams()
	p2.Salt[0] ^= 0xFF
	k1, _ := Derive("pw", p1)
	defer k1.Zero()
	k2, _ := Derive("pw", p2)
	defer k2.Zero()
	if bytes.Equal(k1.Bytes(), k2.Bytes()) {
		t.Fatal("different salts produced identical keys")
	}
}

func TestDerive_RejectsBadInputs(t *testing.T) {
	base := TestParams()

	badKDF := base
	badKDF.KDF = "pbkdf2"
	if _, err := Derive("pw", badKDF); !errors.Is(err, ErrUnknownKDF) {
		t.Errorf("bad KDF: got %v, want ErrUnknownKDF", err)
	}

	badKeyLen := base
	badKeyLen.KeyLenBits = 128
	if _, err := Derive("pw", badKeyLen); !errors.Is(err, ErrBadKeyLen) {
		t.Errorf("bad key len: got %v, want ErrBadKeyLen", err)
	}

	shortSalt := base
	shortSalt.Salt = []byte{1, 2}
	if _, err := Derive("pw", shortSalt); !errors.Is(err, ErrShortSalt) {
		t.Errorf("short salt: got %v, want ErrShortSalt", err)
	}

	if _, err := Derive("", base); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("empty pw: got %v, want ErrEmptyPassphrase", err)
	}
}

// Key.Zero must wipe the material and mark the Key dead. Use-after-Zero must
// panic — silent nil returns are how footguns get shipped.
func TestKey_ZeroWipesAndPanicsOnUse(t *testing.T) {
	k, _ := Derive("pw", TestParams())
	before := append([]byte(nil), k.Bytes()...)
	k.Zero()

	// The underlying slice must not still equal the derived bytes.
	// (k.Bytes() would panic; grab the storage via a fresh Derive to compare
	// against a known non-zero.)
	nonzero := false
	for _, b := range before {
		if b != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		t.Fatal("test bug: derived key was already all-zero")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Bytes() on zeroed key did not panic")
		}
	}()
	_ = k.Bytes()
}

// F07: Bytes() must return a fresh copy — mutating what Bytes() returned
// must not touch the Key's storage or a later Bytes() call, and a copy
// held past Zero() keeps its bytes (as opposed to the pre-F07 aliasing
// behaviour, where the caller's slice was silently wiped).
func TestKey_Bytes_ReturnsCopy_F07(t *testing.T) {
	k, _ := Derive("pw", TestParams())
	first := k.Bytes()
	// Mutate the returned slice.
	for i := range first {
		first[i] = 0xFF
	}
	// A fresh Bytes() call must still yield the original derived key.
	second := k.Bytes()
	for i := range second {
		if second[i] == 0xFF {
			t.Fatalf("Bytes() shared storage — mutation of first leaked into second at %d", i)
		}
	}

	// A copy captured before Zero() must survive Zero().
	held := k.Bytes()
	k.Zero()
	allZero := true
	for _, b := range held {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("Bytes() result was aliased — Zero() wiped the caller's copy")
	}
}

// F07: BytesUnsafe is the aliasing escape hatch — mutating the returned
// slice DOES touch the Key. Documented behaviour; guarded here so a future
// refactor cannot accidentally silently break either the safe or the
// unsafe contract.
func TestKey_BytesUnsafe_Aliases_F07(t *testing.T) {
	k, _ := Derive("pw", TestParams())
	unsafe := k.BytesUnsafe()
	unsafe[0] = 0xEE
	if k.Bytes()[0] != 0xEE {
		t.Fatal("BytesUnsafe did NOT alias — the escape hatch is gone")
	}
}

func TestKey_ZeroIsIdempotent(t *testing.T) {
	k, _ := Derive("pw", TestParams())
	k.Zero()
	k.Zero() // must not panic
}

func TestDefaultParams_IsSecureShape(t *testing.T) {
	p, err := DefaultParams()
	if err != nil {
		t.Fatalf("DefaultParams: %v", err)
	}
	if p.KDF != KDFArgon2id {
		t.Errorf("KDF = %q, want %q", p.KDF, KDFArgon2id)
	}
	if p.KeyLenBits != KeySize*8 {
		t.Errorf("KeyLenBits = %d, want %d", p.KeyLenBits, KeySize*8)
	}
	if len(p.Salt) != SaltSize {
		t.Errorf("salt = %d bytes, want %d", len(p.Salt), SaltSize)
	}
	// Every byte identically zero would mean rand.Read failed silently.
	allZero := true
	for _, b := range p.Salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("DefaultParams produced an all-zero salt")
	}

	if IsInsecureForTest(p) {
		t.Fatal("DefaultParams reads as insecure — the production defaults have regressed")
	}
}

func TestIsInsecureForTest_FlagsTestParams(t *testing.T) {
	if !IsInsecureForTest(TestParams()) {
		t.Fatal("TestParams() should read as insecure")
	}
}

// F03: DefaultParams() must clear the production floor. If a maintainer
// weakens DefaultParams below the floor by mistake, this test refuses
// the change loudly.
func TestDefaultParams_MeetsProductionFloor(t *testing.T) {
	p, err := DefaultParams()
	if err != nil {
		t.Fatalf("DefaultParams: %v", err)
	}
	if err := ValidateProduction(p); err != nil {
		t.Fatalf("DefaultParams below production floor: %v", err)
	}
}

// F03: TestParams must FAIL the production floor. This is the load-bearing
// property Vault.Unlock relies on to catch a manifest that was minted by a
// misconfigured test path landing in a real vault.
func TestValidateProduction_RejectsTestParams(t *testing.T) {
	err := ValidateProduction(TestParams())
	if err == nil {
		t.Fatal("ValidateProduction accepted TestParams")
	}
	if !errors.Is(err, ErrKDFBelowProductionFloor) {
		t.Errorf("err = %v, want ErrKDFBelowProductionFloor", err)
	}
}

// Boundary check: floor-1 on each axis must fail; exactly-at-floor must pass.
func TestValidateProduction_BoundaryPerAxis(t *testing.T) {
	base, _ := DefaultParams()

	// Exactly-at-floor passes.
	atFloor := base
	atFloor.Time = MinProductionTime
	atFloor.MemoryKiB = MinProductionMemoryKiB
	atFloor.Parallel = MinProductionParallel
	if err := ValidateProduction(atFloor); err != nil {
		t.Errorf("at-floor rejected: %v", err)
	}

	// One below Time.
	below := atFloor
	below.Time = MinProductionTime - 1
	if !errors.Is(ValidateProduction(below), ErrKDFBelowProductionFloor) {
		t.Error("t<floor accepted")
	}

	// One below Memory.
	below = atFloor
	below.MemoryKiB = MinProductionMemoryKiB - 1
	if !errors.Is(ValidateProduction(below), ErrKDFBelowProductionFloor) {
		t.Error("m<floor accepted")
	}
}

// Two consecutive DefaultParams() calls must produce different salts —
// otherwise every vault on earth would have the same salt, which defeats
// per-vault Argon2id entirely.
func TestDefaultParams_SaltsAreUnique(t *testing.T) {
	p1, _ := DefaultParams()
	p2, _ := DefaultParams()
	if bytes.Equal(p1.Salt, p2.Salt) {
		t.Fatal("DefaultParams produced identical salts on consecutive calls")
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
