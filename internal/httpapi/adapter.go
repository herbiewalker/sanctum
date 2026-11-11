package httpapi

import (
	"crypto/rand"
	"io"

	"github.com/herbiewalker/sanctum/internal/blobstore"
)

// The Vault interface (server.go) intentionally does not expose the concrete
// *blobstore.Store, because tests want a minimal surface to stub. But the
// restore handler needs to stream a blob and get verify-on-close. Two thin
// helpers below bridge that:
//
//   - openBlob is the single call restore.go makes. It reaches through the
//     Vault to the real blobstore.Store when running against production and
//     to a test-side implementation via BlobOpener in tests.
//   - readRand wraps crypto/rand purely so tests could stub randomness if
//     they ever needed to (not currently).

// BlobOpener is what the real vault + a test can both satisfy. It exists so
// this package does not have to import all of vault.
type BlobOpener interface {
	OpenBlob(ownerID, id string) (io.ReadCloser, error)
}

// Assert *realVault satisfies BlobOpener via OpenBlob. See server.go.
func (r *realVault) OpenBlob(ownerID, id string) (io.ReadCloser, error) {
	// The real blob store is *blobstore.Store, whose Get returns *blobstore.Reader,
	// which implements io.Reader + io.Closer. Wrap it as an io.ReadCloser.
	br, err := r.v.Store().Get(ownerID, id)
	if err != nil {
		return nil, err
	}
	return blobReadCloser{r: br}, nil
}

// blobReadCloser adapts *blobstore.Reader (already Read + Close) to the
// stdlib io.ReadCloser interface.
type blobReadCloser struct{ r *blobstore.Reader }

func (b blobReadCloser) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b blobReadCloser) Close() error               { return b.r.Close() }

// openBlob wires the Vault to a BlobOpener. Panics on a misuse (a Vault that
// does not implement BlobOpener) — a bug worth catching at startup, not a
// runtime error path.
func openBlob(v Vault, ownerID, id string) (io.ReadCloser, error) {
	bo, ok := v.(BlobOpener)
	if !ok {
		panic("httpapi: Vault implementation does not satisfy BlobOpener")
	}
	return bo.OpenBlob(ownerID, id)
}

// readRand fills p from crypto/rand. Wrapped so tests could stub it later.
func readRand(p []byte) (int, error) { return rand.Read(p) }
