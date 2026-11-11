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
//go:build !linux

package vault

// isTmpfsBacked has no meaningful implementation off Linux — Windows and
// macOS do not expose a comparable "this mount is RAM-backed" flag. On those
// platforms the caller must set Paths.AllowNonTmpfsTmpDir=true explicitly
// (dev boxes, CI on non-Linux runners). We report false with no error so the
// caller's opt-in check is what governs whether Vault.New proceeds.
func isTmpfsBacked(path string) (bool, error) {
	return false, nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
