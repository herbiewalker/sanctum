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

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenInMemory_AppliesV1Schema(t *testing.T) {
	idx, err := OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	defer idx.Close()
	if got := idx.SchemaVersion(); got != CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got, CurrentSchemaVersion)
	}

	// Every schema-v1 table exists — a rough shape check that catches a
	// migration that forgot to run.
	for _, table := range []string{"owner", "owner_backup_password", "backup",
		"backup_table_count", "event", "meta"} {
		row := idx.DB().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table)
		var name string
		if err := row.Scan(&name); err != nil || name != table {
			t.Errorf("table %q missing after migration", table)
		}
	}
}

// A second migrate on an already-current DB must be a no-op — the harness
// remembers what has landed.
func TestMigrate_IsIdempotent(t *testing.T) {
	idx, err := OpenInMemory()
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	defer idx.Close()
	// Re-run: must not error.
	if err := migrate(idx.DB()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestOwner_CreateAndGet(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()

	o := Owner{
		ID: "01OWNER", Label: "the operator", LoginUsername: "root",
		CreatedAt: 1_700_000_000,
	}
	auth := OwnerAuth{
		KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"),
		Iterations: 600_000, Hash: []byte("hash-goes-here"),
	}
	if err := idx.CreateOwner(o, auth); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}

	got, err := idx.GetOwner(o.ID)
	if err != nil {
		t.Fatalf("GetOwner: %v", err)
	}
	if got.Label != o.Label || got.LoginUsername != o.LoginUsername {
		t.Errorf("GetOwner = %+v, want label/username to match", got)
	}
}

func TestOwner_GetMissing(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	if _, err := idx.GetOwner("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// D-13: password entries walk in last_used_at DESC, added_at DESC order —
// that's the trial-decrypt ordering ingest relies on (F18).
func TestBackupPassword_ListOrder(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	seedOwner(t, idx, "OWNER1")

	// Three entries, added in the order p1, p2, p3.
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(idx.AddBackupPassword(BackupPassword{ID: "p1", OwnerID: "OWNER1", Label: "old", Passphrase: []byte("aaa"), AddedAt: 100}))
	must(idx.AddBackupPassword(BackupPassword{ID: "p2", OwnerID: "OWNER1", Label: "mid", Passphrase: []byte("bbb"), AddedAt: 200}))
	must(idx.AddBackupPassword(BackupPassword{ID: "p3", OwnerID: "OWNER1", Label: "new", Passphrase: []byte("ccc"), AddedAt: 300}))

	// Mark p1 as most recently used.
	_, err := idx.DB().Exec(`UPDATE owner_backup_password SET last_used_at = 500 WHERE id = 'p1'`)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	list, err := idx.ListBackupPasswords("OWNER1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Expected order: p1 (last_used 500) first, then p3 (added 300), then p2 (added 200).
	got := []string{list[0].ID, list[1].ID, list[2].ID}
	want := []string{"p1", "p3", "p2"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order[%d] = %s, want %s (full: %v)", i, got[i], want[i], got)
		}
	}
}

// Deleting a password sets any backup.opened_by_password_id that referenced
// it to NULL — the ON DELETE SET NULL FK. Ingest can then rediscover it.
func TestBackupPassword_DeleteSetsBackupPointerNull(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	seedOwner(t, idx, "O")

	pw := BackupPassword{ID: "PW1", OwnerID: "O", Label: "l", Passphrase: []byte("x"), AddedAt: 1}
	if err := idx.AddBackupPassword(pw); err != nil {
		t.Fatal(err)
	}

	b := Backup{
		ID: "B1", OwnerID: "O", SHA256: "aa", SizeBytes: 100, IngestedAt: 1,
		Source: "upload", ContainerVersion: 1, KDFIterations: 600_000,
		VerifyStatus: "ok", OpenedByPasswordID: strPtr("PW1"),
		BlobPath: "O/B1.tryst",
	}
	if err := idx.InsertBackup(b, nil); err != nil {
		t.Fatal(err)
	}

	if err := idx.DeleteBackupPassword("PW1"); err != nil {
		t.Fatal(err)
	}
	got, err := idx.ListBackups("O")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].OpenedByPasswordID != nil {
		t.Errorf("after delete: got %+v, want opened_by_password_id NULL", got)
	}
}

// F13: duplicate SHA-256 for the same owner returns ErrDuplicate.
func TestBackup_DuplicateSHA(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	seedOwner(t, idx, "O")

	b := Backup{
		ID: "B1", OwnerID: "O", SHA256: "deadbeef", SizeBytes: 1, IngestedAt: 1,
		Source: "upload", ContainerVersion: 1, KDFIterations: 600_000,
		VerifyStatus: "ok", BlobPath: "O/B1.tryst",
	}
	if err := idx.InsertBackup(b, nil); err != nil {
		t.Fatal(err)
	}
	b2 := b
	b2.ID = "B2"
	err := idx.InsertBackup(b2, nil)
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
}

func TestBackup_InsertAndCounts(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	seedOwner(t, idx, "O")

	mediaBytes := int64(42_000)
	b := Backup{
		ID: "B1", OwnerID: "O", SHA256: "aa", SizeBytes: 500, IngestedAt: 1,
		Source: "upload", ContainerVersion: 1, KDFIterations: 600_000,
		VerifyStatus: "ok", BlobPath: "O/B1.tryst",
	}
	tc := map[string]TableCount{
		"encounters": {RowCount: 3},
		"partners":   {RowCount: 1},
		"__media__":  {RowCount: 2, TotalBytes: &mediaBytes},
	}
	if err := idx.InsertBackup(b, tc); err != nil {
		t.Fatal(err)
	}

	got, err := idx.GetTableCounts("B1")
	if err != nil {
		t.Fatal(err)
	}
	if got["encounters"].RowCount != 3 || got["partners"].RowCount != 1 {
		t.Errorf("row counts wrong: %+v", got)
	}
	media := got["__media__"]
	if media.RowCount != 2 || media.TotalBytes == nil || *media.TotalBytes != mediaBytes {
		t.Errorf("__media__ = %+v, want RowCount=2 TotalBytes=42000", media)
	}
}

// --- seal / unseal ----------------------------------------------------------

func TestSealBytes_RoundTripAndAuth(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("this is a small sealed thing")

	sealed, err := SealBytes(key, nil, plaintext)
	if err != nil {
		t.Fatalf("SealBytes: %v", err)
	}
	got, err := UnsealBytes(key, nil, sealed)
	if err != nil {
		t.Fatalf("UnsealBytes: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch")
	}

	// Wrong key => ErrSealAuth
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 0x01
	if _, err := UnsealBytes(wrong, nil, sealed); !errors.Is(err, ErrSealAuth) {
		t.Errorf("wrong key: err = %v, want ErrSealAuth", err)
	}

	// Flipped ciphertext byte => ErrSealAuth
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := UnsealBytes(key, nil, tampered); !errors.Is(err, ErrSealAuth) {
		t.Errorf("tampered: err = %v, want ErrSealAuth", err)
	}

	// Flipped header byte => ErrSealAuth (AAD binds the header)
	badHdr := append([]byte(nil), sealed...)
	badHdr[5] ^= 0x01 // version byte
	// Version-byte flip actually triggers ErrSealBadVersion first, which is
	// the more informative error — accept either.
	if _, err := UnsealBytes(key, nil, badHdr); err == nil {
		t.Error("tampered version accepted")
	}
}

// F05: SealBytes+UnsealBytes with a real binding round-trip; a changed
// binding on unseal surfaces as ErrSealManifestOutOfBand, not ErrSealAuth.
func TestSealBytes_ManifestBindingF05(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	binding := []byte("manifest-v1")
	sealed, err := SealBytes(key, binding, []byte("payload"))
	if err != nil {
		t.Fatalf("SealBytes: %v", err)
	}

	// Correct binding: round-trip works.
	if got, err := UnsealBytes(key, binding, sealed); err != nil || string(got) != "payload" {
		t.Fatalf("round-trip: err=%v got=%q", err, got)
	}

	// Changed binding: manifest-out-of-band, BEFORE any AEAD attempt.
	if _, err := UnsealBytes(key, []byte("manifest-v2"), sealed); !errors.Is(err, ErrSealManifestOutOfBand) {
		t.Errorf("changed binding: err = %v, want ErrSealManifestOutOfBand", err)
	}

	// Tampered bindHash byte (in header): also out-of-band because our
	// expected hash won't match the tampered stored hash. Belt-and-braces:
	// even if it DID match, GCM AAD covers the bindHash too, so it would
	// fall through to ErrSealAuth.
	tampered := append([]byte(nil), sealed...)
	tampered[8] ^= 0x01
	err = nil
	if _, e := UnsealBytes(key, binding, tampered); e == nil {
		t.Error("tampered bindHash accepted")
	} else if !errors.Is(e, ErrSealManifestOutOfBand) && !errors.Is(e, ErrSealAuth) {
		t.Errorf("tampered bindHash: unexpected err = %v", e)
	}
}

func TestSealBytes_RejectsBadMagic(t *testing.T) {
	key := make([]byte, 32)
	if _, err := UnsealBytes(key, nil, []byte("nope this is not a seal, need at least fifty-two bytes of it xxxxxx")); !errors.Is(err, ErrSealBadMagic) {
		t.Errorf("err = %v, want ErrSealBadMagic", err)
	}
	if _, err := UnsealBytes(key, nil, []byte("SN")); !errors.Is(err, ErrSealTruncated) {
		t.Errorf("truncated: err = %v, want ErrSealTruncated", err)
	}
}

// End-to-end: seal an index to disk, keep .prev, unseal, verify contents.
func TestSealFile_RoundTripWithPrev(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	if err := SealFile(dir, key, nil, []byte("gen1")); err != nil {
		t.Fatalf("SealFile #1: %v", err)
	}
	// Second seal must promote gen1 to .prev.
	if err := SealFile(dir, key, nil, []byte("gen2")); err != nil {
		t.Fatalf("SealFile #2: %v", err)
	}

	primary, err := UnsealFile(dir, key, nil)
	if err != nil {
		t.Fatalf("UnsealFile: %v", err)
	}
	if string(primary) != "gen2" {
		t.Errorf("primary = %q, want gen2", primary)
	}

	// Corrupt the primary => UnsealFile falls back to .prev.
	sealPath := filepath.Join(dir, sealFileName)
	sealed, _ := readAll(sealPath)
	sealed[len(sealed)-1] ^= 0xFF
	writeAll(t, sealPath, sealed)

	fallback, err := UnsealFile(dir, key, nil)
	if err != nil {
		t.Fatalf("UnsealFile fallback: %v", err)
	}
	if string(fallback) != "gen1" {
		t.Errorf("fallback = %q, want gen1 (the previous generation)", fallback)
	}
}

// End-to-end index seal: Serialize the index, SealBytes it, UnsealBytes,
// LoadInto a fresh index, confirm the row survived. This is the round-trip
// M2 is really about.
func TestIndex_SerializeSealUnsealRoundTrip(t *testing.T) {
	idx, _ := OpenInMemory()
	defer idx.Close()
	seedOwner(t, idx, "O")

	b := Backup{
		ID: "B1", OwnerID: "O", SHA256: "aa", SizeBytes: 1, IngestedAt: 1,
		Source: "upload", ContainerVersion: 1, KDFIterations: 600_000,
		VerifyStatus: "ok", BlobPath: "O/B1.tryst",
	}
	if err := idx.InsertBackup(b, map[string]TableCount{"encounters": {RowCount: 5}}); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	raw, err := idx.Serialize(tmp)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// SQLite files start with the magic "SQLite format 3\x00".
	if !bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("Serialize did not produce a SQLite file (first 16 bytes: %q)", raw[:16])
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := SealBytes(key, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnsealBytes(key, nil, sealed)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadInto(restored, tmp)
	if err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	defer loaded.Close()

	got, err := loaded.ListBackups("O")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "B1" {
		t.Errorf("after round-trip: %+v", got)
	}
	tc, err := loaded.GetTableCounts("B1")
	if err != nil {
		t.Fatal(err)
	}
	if tc["encounters"].RowCount != 5 {
		t.Errorf("table_count survived as %+v, want encounters=5", tc)
	}
}

// --- helpers ----------------------------------------------------------------

func seedOwner(t *testing.T, idx *Index, id string) {
	t.Helper()
	err := idx.CreateOwner(
		Owner{ID: id, Label: "test", LoginUsername: id + "-user", CreatedAt: 1},
		OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"), Iterations: 1, Hash: []byte("x")},
	)
	if err != nil {
		t.Fatalf("seed owner %s: %v", id, err)
	}
}

func strPtr(s string) *string { return &s }

func readAll(path string) ([]byte, error) {
	return readAllFile(path)
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
