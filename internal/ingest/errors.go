package ingest

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

import "errors"

// Well-known ingest errors.
//
// Callers pattern-match on these to distinguish "reject and move on" (a
// duplicate, a wrong password, a locked vault) from a genuine problem that
// warrants operator attention. Every rejection also produces an event row
// via LogEvent — see internal/index for the neutral-detail rules.
var (
	// ErrBusy: another ingest is already staging a file (D09). Retry shortly.
	ErrBusy = errors.New("ingest: another ingest is in progress")

	// ErrVaultLocked fires when Ingest is called while the Service is in
	// the LOCKED state (D-4). This is checked before touching input so a
	// hostile file dropped in the inbox during a re-lock window still cannot
	// exercise any parser code.
	ErrVaultLocked = errors.New("ingest: vault locked — unlock before ingest")

	// ErrDuplicate fires when a backup with the same SHA-256 already exists
	// for this owner (F13). The blob on disk is left untouched — it is
	// immutable (D-11).
	ErrDuplicate = errors.New("ingest: backup already exists for this owner (duplicate SHA-256)")

	// ErrNoOwnerPasswords fires when the owner has no entries in their
	// D-13 password set. The operator needs to add at least one before
	// ingest can trial-decrypt anything.
	ErrNoOwnerPasswords = errors.New("ingest: owner has no backup passwords — add one first")

	// ErrRejected wraps a T6 hostile-input rejection. The wrapped error
	// carries the underlying trystbk/blobstore error; the event log carries
	// a short reason code (never encounter content, per N15).
	ErrRejected = errors.New("ingest: file rejected")

	// ErrUnknownOwner fires when the owner id passed to Ingest is not in
	// the index. This is a caller bug — the watcher and HTTP upload paths
	// should validate the owner id against a stable list before calling.
	ErrUnknownOwner = errors.New("ingest: owner not found in index")
)

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
