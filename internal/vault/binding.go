package vault

import (
	"encoding/binary"

	"github.com/herbiewalker/sanctum/internal/vaultkey"
)

// manifestBinding returns the deterministic byte serialization of the
// manifest's KDF stanza. This blob is what SealBytes hashes into the seal
// header (F05) so a tampered manifest.json surfaces as
// ErrSealManifestOutOfBand at unseal, distinct from a wrong-passphrase.
//
// The encoding is deliberately hand-rolled instead of json.Marshal: json
// output is stable for THIS Go version but not a spec, and any future
// field addition to vaultkey.Params would silently change the binding for
// existing seals. Hand-rolling makes the format explicit and lets us
// version it if a new field ever needs to be included.
//
// v1 binding layout:
//
//	"SNBIND-01"                     9 bytes
//	kdf-name-len (u8) + kdf-name   1 + N bytes
//	time                            4 bytes big-endian
//	memoryKiB                       4 bytes big-endian
//	parallel                        1 byte
//	keyLenBits                      4 bytes big-endian
//	salt-len (u16) + salt          2 + M bytes
//
// A future v2 adds a new prefix and Sanctum accepts both while migrating.
func manifestBinding(p vaultkey.Params) []byte {
	const prefix = "SNBIND-01"
	kdfLen := len(p.KDF)
	saltLen := len(p.Salt)
	out := make([]byte, 0, len(prefix)+1+kdfLen+4+4+1+4+2+saltLen)
	out = append(out, prefix...)
	out = append(out, byte(kdfLen))
	out = append(out, p.KDF...)
	out = binary.BigEndian.AppendUint32(out, p.Time)
	out = binary.BigEndian.AppendUint32(out, p.MemoryKiB)
	out = append(out, p.Parallel)
	out = binary.BigEndian.AppendUint32(out, p.KeyLenBits)
	out = binary.BigEndian.AppendUint16(out, uint16(saltLen))
	out = append(out, p.Salt...)
	return out
}
