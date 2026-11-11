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
//go:build linux

package vault

import (
	"fmt"
	"syscall"
)

// Filesystem magic numbers we accept as "tmpfs-like": tmpfs itself and ramfs.
// Both keep their contents in kernel-managed RAM and disappear on unmount —
// which is exactly the property hard constraint 2 needs.
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458F6
)

// isTmpfsBacked reports whether path resides on a tmpfs-like filesystem.
// Returns (false, nil) if it exists on a real disk-backed fs. Returns an
// error only for genuine syscall failures (path missing, permission denied).
func isTmpfsBacked(path string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false, fmt.Errorf("statfs %q: %w", path, err)
	}
	switch uint32(st.Type) {
	case tmpfsMagic, ramfsMagic:
		return true, nil
	}
	return false, nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
