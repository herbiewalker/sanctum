package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/herbiewalker/sanctum/internal/vaultkey"
)

// LayoutVersion of the on-disk vault (DATA_MODEL). Bumped only via the vault
// migration flow, which does not exist yet — a bump lands with a migration
// plan or not at all.
const LayoutVersion = 1

// ManifestFile is the cleartext JSON file at the vault root that carries
// KDF params + layout version. DATA_MODEL: "the only thing that must be
// readable to rebuild from zero. Contains no secrets."
const ManifestFile = "manifest.json"

// Manifest is what LoadOrCreateManifest reads / writes.
type Manifest struct {
	LayoutVersion int             `json:"layout_version"`
	KDF           vaultkey.Params `json:"kdf"` // Argon2id salt + cost — no secret material
	CreatedAt     int64           `json:"created_at"`
}

// LoadOrCreateManifest reads the manifest at dir/manifest.json, or generates
// one with fresh KDF params on first run.
//
// The distinction "loaded" vs "created" is important: on a first-run vault
// we mint a random salt via vaultkey.DefaultParams; on subsequent starts we
// MUST re-use whatever the operator's passphrase was originally salted with,
// otherwise unlock derives a different key and every stored seal fails auth.
// Losing this file is losing the vault, and the file has no secret — so it
// is also the file most worth protecting from silent corruption.
func LoadOrCreateManifest(dir string) (Manifest, bool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, false, fmt.Errorf("vault: mkdir %q: %w", dir, err)
	}
	path := filepath.Join(dir, ManifestFile)

	raw, err := os.ReadFile(path)
	if err == nil {
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return Manifest{}, false, fmt.Errorf("vault: parse manifest: %w", err)
		}
		if m.LayoutVersion != LayoutVersion {
			return Manifest{}, false, fmt.Errorf(
				"vault: manifest layout_version %d != supported %d",
				m.LayoutVersion, LayoutVersion)
		}
		if m.KDF.KDF == "" || len(m.KDF.Salt) == 0 || m.KDF.KeyLenBits == 0 {
			return Manifest{}, false, errors.New("vault: manifest KDF params incomplete")
		}
		return m, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, false, fmt.Errorf("vault: read manifest: %w", err)
	}

	// First run: mint params, write manifest atomically (.tmp + rename).
	params, err := vaultkey.DefaultParams()
	if err != nil {
		return Manifest{}, false, err
	}
	m := Manifest{
		LayoutVersion: LayoutVersion,
		KDF:           params,
		CreatedAt:     nowUnix(),
	}
	if err := writeManifest(path, m); err != nil {
		return Manifest{}, false, err
	}
	return m, true, nil
}

// writeManifest writes atomically. A crash between .tmp and rename leaves
// the old manifest intact (or nothing, if this was the first run — recoverable).
func writeManifest(path string, m Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("vault: write manifest tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: rename manifest: %w", err)
	}
	return nil
}
