package vault

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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// StateFile is the cleartext sibling of manifest.json that records
// operational state the scheduler needs to consult WHILE THE VAULT IS
// LOCKED (D-18). It carries no secret material — only wall-clock timestamps
// the operator would already see in Sanctum's logs.
const StateFile = "state.json"

// State is the shape written to disk. Zero values are legal (first run).
type State struct {
	// LockedSince is the unix-seconds timestamp of the most recent Lock
	// transition. Zero when the vault has never been unlocked, or when a
	// subsequent Unlock has cleared it.
	LockedSince int64 `json:"locked_since,omitempty"`

	// LastLockedAlertAt is the unix-seconds timestamp of the last
	// "locked since X" alert. Used to debounce the alert across restarts.
	LastLockedAlertAt int64 `json:"last_locked_alert_at,omitempty"`
}

// stateStore serialises reads and writes against a single state.json path.
// One instance per vault, held by the Vault.
type stateStore struct {
	path string
	mu   sync.Mutex
}

func newStateStore(vaultDir string) *stateStore {
	return &stateStore{path: filepath.Join(vaultDir, StateFile)}
}

// Load reads state.json, or returns a zero State on ENOENT.
func (s *stateStore) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *stateStore) loadLocked() (State, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("vault: read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("vault: parse state: %w", err)
	}
	return st, nil
}

// Update reads, mutates, and writes state.json atomically. mutate may return
// an error to abort the write.
func (s *stateStore) Update(mutate func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	mutate(&st)
	return s.writeLocked(st)
}

func (s *stateStore) writeLocked(st State) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("vault: write state tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: rename state: %w", err)
	}
	return nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
