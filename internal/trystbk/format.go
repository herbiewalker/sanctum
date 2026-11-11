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
// Package trystbk reads Tryst's TRYSTBK1 backup container.
//
// This file is the format specification expressed as constants, and nothing
// else — no parsing logic lives here. It is transcribed from Tryst's
// docs/EXPORT_FORMAT.md, which is the contract Sanctum implements against
// rather than sharing code with the app (ADR D-6, D-7).
//
// The container:
//
//	┌──────────────── cleartext header, 29 bytes ────────────────┐
//	│ magic       8 bytes   ASCII "TRYSTBK1"                     │
//	│ version     1 byte    format version (1)                   │
//	│ salt       16 bytes   random, for the password KDF         │
//	│ iterations  4 bytes   big-endian int32, PBKDF2 count       │
//	└────────────────────────────────────────────────────────────┘
//	  ↓ everything after the header is one AEAD stream
//	AES-256-GCM-HKDF streaming, 1 MiB segments, AD = "tryst-backup-v1",
//	key = PBKDF2-HMAC-SHA256(password, salt, iterations) → 32 bytes
//	  ↓ whose plaintext is a ZIP containing
//	data.json   { "schemaVersion": N, "tables": { <table>: [ {col: value}, … ] } }
//	media/<id>  decrypted photo bytes, re-encrypted by the container
//
// If this file and Tryst's actual behaviour ever disagree, the app's behaviour
// wins and the spec is a Tryst-side bug to file (D-7).
package trystbk

// Header layout. HeaderSize is asserted against its parts in the tests, so a
// future format revision cannot silently desynchronise the offsets.
const (
	// Magic is the 8-byte ASCII prefix every container starts with.
	Magic = "TRYSTBK1"

	MagicSize      = 8
	VersionSize    = 1
	SaltSize       = 16
	IterationsSize = 4

	// HeaderSize is the total cleartext prefix before the AEAD stream begins.
	HeaderSize = MagicSize + VersionSize + SaltSize + IterationsSize // 29

	// FormatVersion1 is the original container version. A reader
	// must keep handling every version it has ever stored, forever — blobs
	// already in the vault do not get upgraded (DATA_MODEL, layout rules).
	FormatVersion1 = 1

	// FormatVersion2 is what Tryst writes since QOL-5 (v0.6.x). The crypto is
	// byte-for-byte the same as v1 (same KDF, AEAD and associated data); the only
	// difference is an optional settings.json entry inside the ZIP, which Sanctum
	// stores without reading (unknown entries are tolerated, never opened).
	FormatVersion2 = 2
)

// Streaming AEAD parameters. These must match what Tryst encrypts with
// exactly; a mismatch does not produce a helpful error, it produces an
// authentication failure indistinguishable from a wrong password.
const (
	// AssociatedData is bound into every segment's authentication tag.
	AssociatedData = "tryst-backup-v1"

	// HKDFAlg is the hash used for HKDF key derivation inside the stream.
	HKDFAlg = "SHA256"

	// KeySizeBytes is the AES-256 key size, and also the PBKDF2 output length.
	KeySizeBytes = 32

	// SegmentSize is the ciphertext segment size: 1 MiB.
	SegmentSize = 1 << 20

	// FirstSegmentOffset is 0 because Sanctum hands the AEAD reader a stream
	// that already has the cleartext header consumed.
	FirstSegmentOffset = 0
)

// PBKDF2 iteration bounds.
//
// The iteration count is read from the container header, which means it is
// ATTACKER-CONTROLLED: a crafted backup dropped in the inbox (THREAT_MODEL T6)
// could claim math.MaxInt32 and freeze the service deriving a key that will
// never be used. Tryst bounds it on import for exactly this reason and Sanctum
// mirrors the bound rather than inventing its own.
//
// The lower bound matters too: a backup claiming 1 iteration is either corrupt
// or hostile, and accepting it would silently weaken the KDF.
const (
	MinIterations = 100_000
	MaxIterations = 5_000_000

	// DefaultIterations is what Tryst currently writes. Recorded for reference
	// only — always read the actual count from the header.
	DefaultIterations = 600_000
)

// MaxBackupBytes bounds the size of the DECRYPTED backup body Sanctum will
// hold in memory during inspection.
//
// Real Tryst backups today are ~10^2 MB (largest observed: 34 MB, 2026-07).
// 512 MiB leaves ample room for the ROADMAP_FUTURE video-attachment work while
// still being small enough that a hostile file cannot exhaust the container's
// memory limit (deploy/docker-compose.yml sets 512M by default; the mismatch
// is intentional — the OOM kill is a cleaner failure than a partial success).
//
// Enforced by wrapping the AEAD stream in io.LimitReader before io.Copy.
const MaxBackupBytes = 1 << 29 // 512 MiB

// Expected ZIP entries.
const (
	// EntryDataJSON is the generic table dump. Sanctum reads schemaVersion and
	// per-table row COUNTS from it and nothing else (DATA_MODEL: counts, never
	// content).
	EntryDataJSON = "data.json"

	// EntryMediaPrefix is the directory holding decrypted photo blobs. D-15:
	// v1 counts these from the central directory only, and NEVER extracts them.
	// The N19 test proves it by placing a media entry that would fail Open().
	EntryMediaPrefix = "media/"
)

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
