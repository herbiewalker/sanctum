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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Header is the 29-byte cleartext prefix of every TRYSTBK1 container.
//
// It carries the salt and the KDF cost, which are needed to derive the key that
// authenticates the rest of the stream. Everything in this struct is
// ATTACKER-CONTROLLED — a file dropped in the inbox can claim anything here —
// so ParseHeader validates before returning, and the caller does not read a
// field it has not validated (see MaxIterations for the classic pitfall).
type Header struct {
	Version    int
	Salt       [SaltSize]byte
	Iterations int
}

// Well-known parse errors. Callers pattern-match on these to distinguish
// "this file was never a TRYSTBK1 in the first place" (magic mismatch, wrong
// version) from "this file's header claims something invalid" (iterations out
// of range). The former is a rejection with no further work; the latter is a
// rejection *and* a hint that the file may be hostile.
var (
	ErrBadMagic        = errors.New("trystbk: bad magic — not a TRYSTBK1 container")
	ErrUnsupportedVer  = errors.New("trystbk: unsupported container version")
	ErrIterationsRange = errors.New("trystbk: PBKDF2 iterations out of bounds")
	ErrHeaderTruncated = errors.New("trystbk: header truncated")
)

// ParseHeader reads exactly HeaderSize bytes and returns a validated Header.
//
// After success, r's position is on the first byte of the AEAD stream — the
// caller can hand r straight to the decrypting reader with no further seeking.
// On failure r's position is undefined; callers must not resume reading from it.
func ParseHeader(r io.Reader) (Header, error) {
	var buf [HeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrHeaderTruncated
		}
		return Header{}, fmt.Errorf("trystbk: read header: %w", err)
	}

	// Magic. This is the cheapest filter — a random file dropped in the inbox
	// almost never starts with these 8 bytes, so it exits before any KDF work.
	if string(buf[0:MagicSize]) != Magic {
		return Header{}, ErrBadMagic
	}

	// Version. Sanctum keeps handling every version it has ever stored,
	// forever (DATA_MODEL layout rules) — a v2 blob already in the vault must
	// still open on a Sanctum that only knows v1. But an *unknown* version
	// arriving fresh means either a Tryst upgrade Sanctum has not caught up
	// with, or a hostile file; either way, reject cleanly rather than guess.
	version := int(buf[MagicSize])
	if version != FormatVersion1 && version != FormatVersion2 {
		return Header{}, fmt.Errorf("%w: %d", ErrUnsupportedVer, version)
	}

	h := Header{Version: version}
	copy(h.Salt[:], buf[MagicSize+VersionSize:MagicSize+VersionSize+SaltSize])

	// Iterations: big-endian int32 per EXPORT_FORMAT.md. Read as uint32 first
	// because a value with the sign bit set (i.e. > 2^31-1) is meaningless as
	// a signed count and would flip negative — better to catch it here as
	// "out of bounds" than to let int arithmetic wrap silently downstream.
	itersRaw := binary.BigEndian.Uint32(buf[MagicSize+VersionSize+SaltSize:])
	iters := int64(itersRaw)
	if iters < MinIterations || iters > MaxIterations {
		return Header{}, fmt.Errorf("%w: %d (accepted %d..%d)",
			ErrIterationsRange, iters, MinIterations, MaxIterations)
	}
	h.Iterations = int(iters)

	return h, nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
