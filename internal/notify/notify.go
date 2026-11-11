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
// Package notify is Sanctum's outbound-alert surface.
//
// Alerts are values written to a directory the host watches (D-18). Sanctum
// never talks to Unraid directly — it just drops a JSON file, and a host-side
// User Script picks it up and calls `/usr/local/emhttp/webGui/scripts/notify`.
// The container never mounts a host binary; the host script never reads
// Sanctum internals.
//
// This package must never carry sensitive content into an intent (N15).
// Subjects and bodies are set by callers; the FileDropNotifier does no
// interpolation beyond what the caller provided.
package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Severity mirrors the levels the Unraid notify helper accepts, mapped by
// the dispatcher script. Kept as a small enum so we cannot accidentally
// invent a new level that has no dispatcher mapping.
type Severity string

const (
	SeverityNormal  Severity = "normal"
	SeverityWarning Severity = "warning"
	SeverityAlert   Severity = "alert"
)

// Kind classifies an intent. Written to the file so the dispatcher (and log
// scrapers) can filter without parsing the body.
type Kind string

const (
	KindStaleness    Kind = "staleness"
	KindVerifyFailed Kind = "verify_failed"
	KindPruned       Kind = "pruned"
	KindLockedSince  Kind = "locked_since"
	KindUpdate       Kind = "update"
	KindTest         Kind = "test"
)

// SchemaVersion of the intent file. Bumped only via ADR (D-18).
const SchemaVersion = 1

// MaxBodyBytes bounds the body field. Keeps the file size predictable and
// discourages callers from stuffing details in.
const MaxBodyBytes = 4096

// Intent is the payload written to the drop directory.
type Intent struct {
	Schema     int      `json:"schema"`
	At         int64    `json:"at"`
	Severity   Severity `json:"severity"`
	Kind       Kind     `json:"kind"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	OwnerLabel string   `json:"owner_label,omitempty"`
}

// Notifier is the interface every alerting code path uses. Two implementations
// live here: FileDropNotifier (production, D-18) and NullNotifier (tests / a
// vault run without a configured drop directory).
type Notifier interface {
	Notify(Intent) error
}

// NullNotifier discards intents. Used by tests and by any deployment that
// explicitly disables notifications (SANCTUM_NOTIFY_DIR unset).
type NullNotifier struct{}

func (NullNotifier) Notify(Intent) error { return nil }

// FileDropNotifier writes intents as JSON files into a pending/ subdirectory
// of the configured drop dir. Filenames encode time to keep the dispatcher's
// glob ordering natural (`YYYYmmddTHHMMSSZ-<counter>-<kind>.json`).
type FileDropNotifier struct {
	dir     string
	pending string
	now     func() time.Time
	counter atomic.Uint64
	mu      sync.Mutex // serialises writes so counter+rename is deterministic
}

// NewFileDropNotifier prepares the drop directory. The pending/ subdir is
// created; sent/ and failed/ are the dispatcher's business and this code
// deliberately does not touch them.
func NewFileDropNotifier(dir string, now func() time.Time) (*FileDropNotifier, error) {
	if dir == "" {
		return nil, errors.New("notify: empty drop directory")
	}
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o755); err != nil {
		return nil, fmt.Errorf("notify: mkdir %q: %w", pending, err)
	}
	if now == nil {
		now = time.Now
	}
	return &FileDropNotifier{dir: dir, pending: pending, now: now}, nil
}

// Dir returns the configured drop directory.
func (f *FileDropNotifier) Dir() string { return f.dir }

// Notify writes one intent atomically (.tmp + rename). A crash between tmp
// and rename leaves nothing visible to the dispatcher.
func (f *FileDropNotifier) Notify(in Intent) error {
	if err := validate(in); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if in.Schema == 0 {
		in.Schema = SchemaVersion
	}
	if in.At == 0 {
		in.At = f.now().Unix()
	}

	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return fmt.Errorf("notify: marshal: %w", err)
	}
	raw = append(raw, '\n')

	ts := f.now().UTC().Format("20060102T150405Z")
	n := f.counter.Add(1)
	name := fmt.Sprintf("%s-%06d-%s.json", ts, n, in.Kind)
	final := filepath.Join(f.pending, name)
	tmp := final + ".tmp"

	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("notify: write tmp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("notify: rename: %w", err)
	}
	return nil
}

func validate(in Intent) error {
	switch in.Severity {
	case SeverityNormal, SeverityWarning, SeverityAlert:
	default:
		return fmt.Errorf("notify: invalid severity %q", in.Severity)
	}
	switch in.Kind {
	case KindStaleness, KindVerifyFailed, KindPruned, KindLockedSince, KindUpdate, KindTest:
	default:
		return fmt.Errorf("notify: invalid kind %q", in.Kind)
	}
	if in.Subject == "" {
		return errors.New("notify: subject required")
	}
	if len(in.Body) > MaxBodyBytes {
		return fmt.Errorf("notify: body exceeds %d bytes", MaxBodyBytes)
	}
	return nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
