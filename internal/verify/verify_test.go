package verify

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/trystbk"
)

// The same synthetic-backup writer that ingest's tests use, kept local per
// the "no shared TRYSTBK1 writer" hard rule.
func buildSyntheticBackup(t *testing.T, password string, zipBody []byte) []byte {
	t.Helper()
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.Write(hdr.Bytes())
	w, err := aead.NewEncryptingWriter(&out, []byte(trystbk.AssociatedData))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(zipBody); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func buildMinimalZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	_, _ = f.Write([]byte(`{"schemaVersion":15,"tables":{"encounters":[{"id":1}]}}`))
	_ = zw.Close()
	return buf.Bytes()
}

type env struct {
	svc     *Service
	store   *blobstore.Store
	idx     *index.Index
	ownerID string
	pwID    string
	pw      string
	backup  index.Backup
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	store, err := blobstore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	ownerID := "owner-1"
	if err := idx.CreateOwner(
		index.Owner{ID: ownerID, Label: "test", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte{1}, Iterations: 1, Hash: []byte{1}},
	); err != nil {
		t.Fatal(err)
	}
	pwID := "pw-1"
	pw := "correct-horse"
	if err := idx.AddBackupPassword(index.BackupPassword{
		ID: pwID, OwnerID: ownerID, Label: "primary",
		Passphrase: []byte(pw), AddedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// Build a synthetic backup, store it, insert index row.
	blob := buildSyntheticBackup(t, pw, buildMinimalZip(t))
	backupID := "b1"
	if _, err := store.Put(ownerID, backupID, bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	shaBytes := sha256.Sum256(blob)
	sha := hexOf(shaBytes[:])
	pwPtr := pwID
	b := index.Backup{
		ID: backupID, OwnerID: ownerID, SHA256: sha, SizeBytes: int64(len(blob)),
		IngestedAt: time.Now().Unix(), Source: "inbox",
		ContainerVersion: 1, KDFIterations: trystbk.MinIterations,
		VerifyStatus: "unverified", OpenedByPasswordID: &pwPtr,
		BlobPath: ownerID + "/" + backupID + ".tryst",
	}
	if err := idx.InsertBackup(b, nil); err != nil {
		t.Fatal(err)
	}
	svc := New(store, idx, func() time.Time { return time.Unix(1_700_000_000, 0) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &env{svc: svc, store: store, idx: idx, ownerID: ownerID, pwID: pwID, pw: pw, backup: b}
}

func hexOf(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0x0f]
	}
	return string(out)
}

// --- happy path -------------------------------------------------------------

func TestOne_HappyPath(t *testing.T) {
	e := setup(t)
	r := e.svc.One(e.backup)
	if r.Status != StatusOK {
		t.Fatalf("status=%q err=%v", r.Status, r.Err)
	}
	// Row should now carry verified_at + status=ok.
	got, err := e.idx.ListBackups(e.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].VerifyStatus != StatusOK {
		t.Errorf("row.status=%q", got[0].VerifyStatus)
	}
	if got[0].VerifiedAt == nil {
		t.Errorf("verified_at nil")
	}
}

// --- forced failures --------------------------------------------------------

func TestOne_HashMismatch_Forced(t *testing.T) {
	e := setup(t)
	// Corrupt the on-disk blob's sidecar so the SHA compare fails on Close.
	sidecar := filepath.Join(e.store.Root(), e.backup.OwnerID, e.backup.ID+".tryst.sha256")
	if err := os.WriteFile(sidecar, []byte("0000000000000000000000000000000000000000000000000000000000000000"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := e.svc.One(e.backup)
	if r.Status != StatusHashMismatch {
		t.Fatalf("status=%q err=%v — hash-mismatch not detected", r.Status, r.Err)
	}
	// One verify_failed event with a hash_mismatch reason.
	var detail string
	if err := e.idx.DB().QueryRow(
		`SELECT detail FROM event WHERE kind='verify_failed' ORDER BY id DESC LIMIT 1`,
	).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !contains(detail, "hash_mismatch") {
		t.Errorf("event detail=%q missing hash_mismatch reason", detail)
	}
}

func TestOne_DecryptFailed_Forced(t *testing.T) {
	e := setup(t)
	// Replace the recorded password with the wrong bytes, and also swap
	// out the passphrase for the row — so neither the recorded winner nor
	// the walk finds a working one.
	if _, err := e.idx.DB().Exec(
		`UPDATE owner_backup_password SET passphrase = ? WHERE id = ?`,
		[]byte("wrong-horse"), e.pwID,
	); err != nil {
		t.Fatal(err)
	}
	r := e.svc.One(e.backup)
	if r.Status != StatusDecryptFailed {
		t.Fatalf("status=%q err=%v — decrypt-failed not detected", r.Status, r.Err)
	}
	var detail string
	if err := e.idx.DB().QueryRow(
		`SELECT detail FROM event WHERE kind='verify_failed' ORDER BY id DESC LIMIT 1`,
	).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !contains(detail, "no_password_matched") {
		t.Errorf("event detail=%q missing no_password_matched reason", detail)
	}
}

func TestOne_PasswordAbsent_Forced(t *testing.T) {
	e := setup(t)
	// Wipe the password set and clear opened_by_password_id.
	if _, err := e.idx.DB().Exec(`DELETE FROM owner_backup_password`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.idx.DB().Exec(
		`UPDATE backup SET opened_by_password_id = NULL WHERE id = ?`, e.backup.ID,
	); err != nil {
		t.Fatal(err)
	}
	// Re-read the backup so OpenedByPasswordID reflects the update.
	rows, err := e.idx.ListBackups(e.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	r := e.svc.One(rows[0])
	if r.Status != StatusPasswordAbsent {
		t.Fatalf("status=%q err=%v", r.Status, r.Err)
	}
}

// --- fallback rescue path ---------------------------------------------------

func TestOne_FallbackWalkFindsWinner(t *testing.T) {
	e := setup(t)
	// Add a second password AT THE FRONT (so we prove ordering doesn't
	// require the winner be first), delete the recorded winner, and
	// verify the walk still finds a working password. The winning row
	// should get its opened_by_password_id updated.
	if err := e.idx.AddBackupPassword(index.BackupPassword{
		ID: "pw-2", OwnerID: e.ownerID, Label: "second",
		Passphrase: []byte(e.pw), AddedAt: 2,
		LastUsedAt: func() *int64 { v := int64(999); return &v }(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.idx.DeleteBackupPassword(e.pwID); err != nil {
		t.Fatal(err)
	}
	// Re-read the row to pick up the FK cascade (opened_by → NULL).
	rows, err := e.idx.ListBackups(e.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	r := e.svc.One(rows[0])
	if r.Status != StatusOK {
		t.Fatalf("fallback failed: status=%q err=%v", r.Status, r.Err)
	}
	// opened_by_password_id should now be pw-2.
	rows, err = e.idx.ListBackups(e.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].OpenedByPasswordID == nil || *rows[0].OpenedByPasswordID != "pw-2" {
		t.Errorf("opened_by not updated: %v", rows[0].OpenedByPasswordID)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || bytes.Contains([]byte(s), []byte(sub))
}
