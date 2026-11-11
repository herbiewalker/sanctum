package vault

import (
	"crypto/sha256"
	"time"

	"github.com/herbiewalker/sanctum/internal/index"
)

// checkpointEvery is how often an unlocked vault looks for unsealed changes.
// Ingest additionally nudges the loop immediately.
const checkpointEvery = 10 * time.Second

// D01: the index lives in memory/tmpfs while unlocked and used to reach the
// array only in Lock(). Any unclean stop (power loss, OOM, a stop that outlives
// the grace period) then lost every owner, password and backup row created in
// the session. The checkpointer seals a fresh generation whenever the index
// content has changed, using the runtime key already held in memory (D-4 is
// unaffected: the key still never reaches disk, only the same AES-GCM seal
// that Lock writes does).

// nudgeCheckpoint asks the checkpointer to run soon. Non-blocking; safe to
// call from any goroutine in any state.
func (v *Vault) nudgeCheckpoint() {
	select {
	case v.nudgeCP <- struct{}{}:
	default:
	}
}

// startCheckpointer launches the loop for this unlock generation. Caller holds
// v.mu (write) and has set v.unlocked.
func (v *Vault) startCheckpointer() {
	stop := make(chan struct{})
	v.stopCP = stop
	v.cpMu.Lock()
	v.lastSum = [32]byte{} // force the first checkpoint to write
	v.cpMu.Unlock()
	// Drain a stale nudge from a previous generation.
	select {
	case <-v.nudgeCP:
	default:
	}
	go func() {
		t := time.NewTicker(checkpointEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			case <-v.nudgeCP:
			}
			if err := v.checkpoint(stop); err != nil {
				v.logger.Warn("vault checkpoint failed; will retry", "err", err.Error())
			}
		}
	}()
}

// Checkpoint seals the index now if it changed since the last seal. Exported
// for tests and for callers that just committed something important.
func (v *Vault) Checkpoint() error {
	v.mu.RLock()
	stop := v.stopCP
	v.mu.RUnlock()
	if stop == nil {
		return nil
	}
	return v.checkpoint(stop)
}

func (v *Vault) checkpoint(stop chan struct{}) error {
	// RLock keeps Lock() (which closes the index) out for the duration.
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.unlocked || v.stopCP != stop {
		return nil // locked, or a newer unlock generation owns the loop
	}
	v.cpMu.Lock()
	defer v.cpMu.Unlock()

	raw, err := v.idx.Serialize(v.paths.TmpDir)
	if err != nil {
		return err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	sum := sha256.Sum256(raw)
	if sum == v.lastSum {
		return nil
	}
	if err := index.SealFile(v.paths.VaultDir, v.key.Bytes(), manifestBinding(v.manifest.KDF), raw); err != nil {
		return err
	}
	v.lastSum = sum
	return nil
}
