package index

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

// F12 / D-5 recovery path — rebuilding backup + backup_table_count from
// the blob store when the sealed index is unrecoverable.
//
// This test drives the full pipeline: build synthetic TRYSTBK1 fixtures,
// Put them into a blob store, throw the index away, Rebuild, assert that
// `backup` and `backup_table_count` come back — and that owner + password
// data is documented-as-unrecoverable (not silently invented).

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/trystbk"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// buildSyntheticBackup is a copy of internal/trystbk/testfixture_test.go's
// syntheticBackup — the trystbk test helper is private to its package, and
// duplicating five lines beats exposing an internal writer that has no
// production caller.
func buildSyntheticBackup(t *testing.T, password string, zipBody []byte) []byte {
	t.Helper()
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var hdr bytes.Buffer
	hdr.WriteString(trystbk.Magic)
	hdr.WriteByte(trystbk.FormatVersion1)
	hdr.Write(salt[:])
	_ = binary.Write(&hdr, binary.BigEndian, uint32(trystbk.MinIterations))

	key := pbkdf2.Key([]byte(password), salt[:], trystbk.MinIterations,
		trystbk.KeySizeBytes, sha256.New)
	aead, err := subtle.NewAESGCMHKDF(key, trystbk.HKDFAlg, trystbk.KeySizeBytes,
		trystbk.SegmentSize, trystbk.FirstSegmentOffset)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	var out bytes.Buffer
	out.Write(hdr.Bytes())
	w, err := aead.NewEncryptingWriter(&out, []byte(trystbk.AssociatedData))
	if err != nil {
		t.Fatalf("enc writer: %v", err)
	}
	if _, err := w.Write(zipBody); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return out.Bytes()
}

// buildMinimalZip: a data.json + one media entry, matching the shapes
// inspectZip expects.
func buildMinimalZip(t *testing.T, schemaVersion int, mediaSize int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	{
		f, _ := zw.Create(trystbk.EntryDataJSON)
		f.Write([]byte(`{"schemaVersion": ` + itoaTest(schemaVersion) +
			`, "tables": {"encounters": [{"id":1}, {"id":2}], "partners": [{"id":1}]}}`))
	}
	if mediaSize > 0 {
		mf, _ := zw.Create("media/a")
		mf.Write(bytes.Repeat([]byte{0xAB}, mediaSize))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRebuild_RecoversBackupsFromBlobs(t *testing.T) {
	// Two synthetic backups, same owner, one password.
	store, err := blobstore.New(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}

	blob1 := buildSyntheticBackup(t, "pw1", buildMinimalZip(t, 15, 4096))
	blob2 := buildSyntheticBackup(t, "pw1", buildMinimalZip(t, 15, 8192))

	if _, err := store.Put("OWNER1", "01BLOB1", bytes.NewReader(blob1)); err != nil {
		t.Fatalf("Put b1: %v", err)
	}
	if _, err := store.Put("OWNER1", "01BLOB2", bytes.NewReader(blob2)); err != nil {
		t.Fatalf("Put b2: %v", err)
	}

	// Fixed clock so IngestedAt assertions are stable.
	now := func() time.Time { return time.Unix(2_000_000_000, 0) }

	idx, res, err := Rebuild(store, []string{"pw1"}, now)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	defer idx.Close()

	if res.BackupsRecovered != 2 {
		t.Errorf("BackupsRecovered = %d, want 2", res.BackupsRecovered)
	}
	if res.BlobsUnopenable != 0 {
		t.Errorf("BlobsUnopenable = %d, want 0", res.BlobsUnopenable)
	}

	// The recovered rows must have the same SHA-256 as the original blobs
	// (proves rebuild wrote the true hash, not a made-up one).
	got, err := idx.ListBackups("OWNER1")
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListBackups: got %d rows, want 2", len(got))
	}
	wantSHAs := map[string]bool{
		toHex(sha256.Sum256(blob1)): true,
		toHex(sha256.Sum256(blob2)): true,
	}
	for _, b := range got {
		if !wantSHAs[b.SHA256] {
			t.Errorf("unexpected SHA %s", b.SHA256)
		}
		if b.Source != "rebuild" {
			t.Errorf("Source = %q, want rebuild", b.Source)
		}
		if b.VerifyStatus != "ok" {
			t.Errorf("VerifyStatus = %q, want ok", b.VerifyStatus)
		}
	}

	// Table counts were recovered too — including the __media__ synthetic row.
	// Pick one backup to check.
	tc, err := idx.GetTableCounts(got[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if tc["encounters"].RowCount != 2 {
		t.Errorf("encounters count = %d, want 2", tc["encounters"].RowCount)
	}
	media, ok := tc["__media__"]
	if !ok || media.RowCount != 1 {
		t.Errorf("__media__ = %+v, want RowCount=1", media)
	}
	if media.TotalBytes == nil || *media.TotalBytes == 0 {
		t.Error("__media__.TotalBytes not populated")
	}
}

// A blob whose password is not in the candidate set stays on disk (immutable)
// and is counted in BlobsUnopenable rather than causing the rebuild to fail.
func TestRebuild_BlobsWithoutPasswordAreCountedNotFailed(t *testing.T) {
	store, _ := blobstore.New(filepath.Join(t.TempDir(), "vault"))

	blobKnown := buildSyntheticBackup(t, "known", buildMinimalZip(t, 15, 0))
	blobUnknown := buildSyntheticBackup(t, "unknown-pw", buildMinimalZip(t, 15, 0))
	store.Put("O", "01KNOWN", bytes.NewReader(blobKnown))
	store.Put("O", "01UNKNW", bytes.NewReader(blobUnknown))

	idx, res, err := Rebuild(store, []string{"known"}, nil)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	defer idx.Close()

	if res.BackupsRecovered != 1 {
		t.Errorf("BackupsRecovered = %d, want 1", res.BackupsRecovered)
	}
	if res.BlobsUnopenable != 1 {
		t.Errorf("BlobsUnopenable = %d, want 1", res.BlobsUnopenable)
	}
}

// A vault with blobs but no candidate passwords is a real error, not a
// silent zero-recovery — otherwise the operator would think everything was
// gone when in fact they just needed to supply the passphrase.
func TestRebuild_RejectsEmptyCandidatesForPopulatedVault(t *testing.T) {
	store, _ := blobstore.New(filepath.Join(t.TempDir(), "vault"))
	blob := buildSyntheticBackup(t, "pw", buildMinimalZip(t, 15, 0))
	store.Put("O", "01AAA", bytes.NewReader(blob))

	_, _, err := Rebuild(store, nil, nil)
	if err != ErrRebuildNoPasswords {
		t.Fatalf("err = %v, want ErrRebuildNoPasswords", err)
	}
}

// An empty vault with no candidates is fine — nothing to open.
func TestRebuild_EmptyVaultIsOK(t *testing.T) {
	store, _ := blobstore.New(filepath.Join(t.TempDir(), "vault"))
	idx, res, err := Rebuild(store, nil, nil)
	if err != nil {
		t.Fatalf("Rebuild empty: %v", err)
	}
	defer idx.Close()
	if res.BackupsRecovered != 0 || len(res.Owners) != 0 {
		t.Errorf("unexpected result: %+v", res)
	}
}

// A blob that was tampered with on disk fails the sidecar verify and is
// counted as BlobsSkipped — no partial-truth landing in the rebuilt index.
func TestRebuild_SkipsTamperedBlobs(t *testing.T) {
	store, _ := blobstore.New(filepath.Join(t.TempDir(), "vault"))
	blob := buildSyntheticBackup(t, "pw", buildMinimalZip(t, 15, 0))
	store.Put("O", "01TAMP", bytes.NewReader(blob))

	// Corrupt the on-disk bytes so the SHA-256 sidecar no longer matches.
	blobPath := filepath.Join(store.Root(), "O", "01TAMP.tryst")
	raw, _ := readAllFile(blobPath)
	raw[0] ^= 0x01
	writeAll(t, blobPath, raw)

	idx, res, err := Rebuild(store, []string{"pw"}, nil)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	defer idx.Close()

	if res.BackupsRecovered != 0 || res.BlobsSkipped != 1 {
		t.Errorf("res = %+v, want BackupsRecovered=0 BlobsSkipped=1", res)
	}
}

func toHex(sum [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[2*i] = hex[b>>4]
		out[2*i+1] = hex[b&0x0F]
	}
	return string(out)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
