package ingest

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/herbiewalker/sanctum/internal/blobstore"
	"github.com/herbiewalker/sanctum/internal/index"
	"github.com/herbiewalker/sanctum/internal/trystbk"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"golang.org/x/crypto/pbkdf2"
)

// setup constructs a fully-populated Service pointed at temp dirs, with one
// owner and one password. Returns everything the tests want to poke at.
type setup struct {
	svc      *Service
	store    *blobstore.Store
	idx      *index.Index
	tmpDir   string
	vaultDir string
	ownerID  string
	pwID     string
	pw       string
	logs     *bytes.Buffer
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	base := t.TempDir()
	tmpDir := filepath.Join(base, "tmp")
	vaultDir := filepath.Join(base, "vault")
	store, err := blobstore.New(vaultDir)
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	idx, err := index.OpenInMemory()
	if err != nil {
		t.Fatalf("index.OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	// Seed one owner + one password.
	ownerID := "OWNER1"
	if err := idx.CreateOwner(
		index.Owner{ID: ownerID, Label: "test", LoginUsername: "u", CreatedAt: 1},
		index.OwnerAuth{KDF: "pbkdf2-sha256", Salt: []byte("saltsaltsalt1234"),
			Iterations: 1, Hash: []byte("x")},
	); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	pwID := "PW1"
	if err := idx.AddBackupPassword(index.BackupPassword{
		ID: pwID, OwnerID: ownerID, Label: "default",
		Passphrase: []byte("correct-horse"), AddedAt: 1,
	}); err != nil {
		t.Fatalf("AddBackupPassword: %v", err)
	}

	// A logger writing to a buffer so tests can scrape for leaks (N15).
	logs := new(bytes.Buffer)
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Deterministic ids: monotonic hex so tests can predict them.
	var seq int
	svc, err := New(store, idx, Options{
		TmpDir: tmpDir,
		NewID: func() string {
			seq++
			return "TESTID000000000000" + itoa2(seq)
		},
		Now:    func() time.Time { return time.Unix(1_700_000_000, 0) },
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &setup{
		svc: svc, store: store, idx: idx, tmpDir: tmpDir, vaultDir: vaultDir,
		ownerID: ownerID, pwID: pwID, pw: "correct-horse", logs: logs,
	}
}

// buildSyntheticBackup: same shape as trystbk/rebuild copies. Kept local to
// this package for the reasons documented in ingest.go — no shared testutil
// exposes a TRYSTBK1 writer.
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

func buildMinimalZip(t *testing.T, schemaVersion int, mediaBytes int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	f.Write([]byte(`{"schemaVersion": ` + itoa2(schemaVersion) + `,
	  "tables": {"encounters": [{"id":1},{"id":2}], "partners": [{"id":1}]}}`))
	if mediaBytes > 0 {
		mf, _ := zw.Create("media/a")
		mf.Write(bytes.Repeat([]byte{0xAB}, mediaBytes))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func itoa2(n int) string {
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

// --- happy path -------------------------------------------------------------

func TestIngest_HappyPath(t *testing.T) {
	s := newSetup(t)

	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 4096))
	res, err := s.svc.IngestReader(s.ownerID, SourceInbox, "foo.tryst", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("IngestReader: %v", err)
	}

	// Result populated correctly.
	if res.OpenedByPasswordID != s.pwID {
		t.Errorf("OpenedByPasswordID = %q, want %q", res.OpenedByPasswordID, s.pwID)
	}
	if res.TrystSchemaVersion != 15 {
		t.Errorf("TrystSchemaVersion = %d, want 15", res.TrystSchemaVersion)
	}
	if res.TableCounts["encounters"] != 2 {
		t.Errorf("encounters count = %d, want 2", res.TableCounts["encounters"])
	}
	if res.TableCounts[trystbk.SyntheticMediaKey] != 1 {
		t.Errorf("__media__ count = %d, want 1", res.TableCounts[trystbk.SyntheticMediaKey])
	}
	if res.SizeBytes != int64(len(blob)) {
		t.Errorf("SizeBytes = %d, want %d", res.SizeBytes, len(blob))
	}

	// Blob landed in the vault.
	blobPath := filepath.Join(s.vaultDir, s.ownerID, res.BackupID+".tryst")
	stored, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read stored blob: %v", err)
	}
	if !bytes.Equal(stored, blob) {
		t.Errorf("stored bytes differ from input — blob was mutated")
	}

	// Index row is what the Result says.
	got, err := s.idx.ListBackups(s.ownerID)
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(got) != 1 || got[0].VerifyStatus != "ok" {
		t.Fatalf("index rows: %+v", got)
	}
	if got[0].OpenedByPasswordID == nil || *got[0].OpenedByPasswordID != s.pwID {
		t.Errorf("row OpenedByPasswordID = %v, want *=%q", got[0].OpenedByPasswordID, s.pwID)
	}

	// last_used_at bumped on the winning password.
	list, _ := s.idx.ListBackupPasswords(s.ownerID)
	if len(list) != 1 || list[0].LastUsedAt == nil {
		t.Errorf("password last_used_at not touched: %+v", list)
	}

	// Tmpfs was cleaned up.
	entries, _ := os.ReadDir(s.tmpDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ingest-") {
			t.Errorf("tmpfs residue: %q", e.Name())
		}
	}
}

// --- locked-vault refusal (D-4 defence in depth) ----------------------------

func TestIngest_LockedVaultRefuses(t *testing.T) {
	s := newSetup(t)
	s.svc.Lock()

	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 0))
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("err = %v, want ErrVaultLocked", err)
	}

	// Nothing landed anywhere.
	got, _ := s.idx.ListBackups(s.ownerID)
	if len(got) != 0 {
		t.Errorf("index has %d rows after locked ingest, want 0", len(got))
	}
	entries, _ := os.ReadDir(filepath.Join(s.vaultDir, s.ownerID))
	if len(entries) != 0 {
		t.Errorf("vault has %d entries after locked ingest, want 0", len(entries))
	}

	// Unlock, retry — must succeed. Proves Lock/Unlock is idempotent.
	s.svc.Unlock()
	if _, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst",
		bytes.NewReader(blob)); err != nil {
		t.Fatalf("after Unlock: %v", err)
	}
}

// --- F13 duplicate detection ------------------------------------------------

func TestIngest_DuplicateBySHA(t *testing.T) {
	s := newSetup(t)
	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 0))

	if _, err := s.svc.IngestReader(s.ownerID, SourceInbox, "first.tryst",
		bytes.NewReader(blob)); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "second.tryst",
		bytes.NewReader(blob))
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second: err = %v, want ErrDuplicate", err)
	}

	// Exactly one row survives.
	got, _ := s.idx.ListBackups(s.ownerID)
	if len(got) != 1 {
		t.Errorf("after duplicate: %d rows, want 1", len(got))
	}
}

// --- T6: wrong password -----------------------------------------------------

func TestIngest_WrongPasswordRejected(t *testing.T) {
	s := newSetup(t)
	blob := buildSyntheticBackup(t, "not-the-configured-pw", buildMinimalZip(t, 15, 0))
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	// Neither vault nor index gained anything.
	got, _ := s.idx.ListBackups(s.ownerID)
	if len(got) != 0 {
		t.Errorf("index has %d rows after wrong-password ingest", len(got))
	}
	entries, _ := os.ReadDir(filepath.Join(s.vaultDir, s.ownerID))
	if len(entries) != 0 {
		t.Errorf("vault has %d entries after wrong-password ingest", len(entries))
	}
	// Event log recorded the rejection with a neutral reason.
	assertEventLogged(t, s.idx, "ingest_rejected", "no_password_matched")
}

// --- T6: flipped byte -------------------------------------------------------

func TestIngest_FlippedByteRejected(t *testing.T) {
	s := newSetup(t)
	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 0))
	// Flip a byte inside the AEAD stream (past the 29-byte header).
	blob[trystbk.HeaderSize+16] ^= 0x01
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	assertEventLogged(t, s.idx, "ingest_rejected", "no_password_matched")
}

// --- T6: bad header ---------------------------------------------------------

func TestIngest_BadHeaderRejected(t *testing.T) {
	s := newSetup(t)
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst",
		bytes.NewReader([]byte("this is not a TRYSTBK1 file at all")))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	assertEventLogged(t, s.idx, "ingest_rejected", "bad_header")
}

// --- T6: absurd iteration count in header -----------------------------------

func TestIngest_AbsurdIterationsRejected(t *testing.T) {
	s := newSetup(t)
	// Build a header with iteration count = 2^32-1, well above MaxIterations.
	var hdr bytes.Buffer
	hdr.WriteString(trystbk.Magic)
	hdr.WriteByte(trystbk.FormatVersion1)
	hdr.Write(bytes.Repeat([]byte{0x00}, trystbk.SaltSize))
	_ = binary.Write(&hdr, binary.BigEndian, uint32(0xFFFFFFFF))
	// Some garbage after the header — never reached, but the parser doesn't
	// care about this.
	hdr.Write(bytes.Repeat([]byte{0x00}, 128))

	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", &hdr)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	assertEventLogged(t, s.idx, "ingest_rejected", "bad_header")
}

// --- T6: Zip-Slip inside decrypted content ----------------------------------

func TestIngest_ZipSlipRejected(t *testing.T) {
	s := newSetup(t)
	// Build a ZIP containing data.json plus an entry with a "../escape" name.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	f.Write([]byte(`{"schemaVersion":1,"tables":{"encounters":[]}}`))
	f, _ = zw.Create("../escape.txt")
	f.Write([]byte("gotcha"))
	_ = zw.Close()

	blob := buildSyntheticBackup(t, s.pw, buf.Bytes())
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	assertEventLogged(t, s.idx, "ingest_rejected", "structural")
}

// --- T6: oversize input ------------------------------------------------------

func TestIngest_OversizeRejected(t *testing.T) {
	s := newSetup(t)
	// A reader that produces MaxBackupBytes + 1 bytes of noise.
	r := io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte{0xAA}, trystbk.MaxBackupBytes)),
		bytes.NewReader([]byte{0xFF}),
	)
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", r)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	// Nothing landed.
	entries, _ := os.ReadDir(filepath.Join(s.vaultDir, s.ownerID))
	if len(entries) != 0 {
		t.Errorf("vault has %d entries after oversize ingest", len(entries))
	}
	// Tmpfs was cleaned up.
	tmps, _ := os.ReadDir(s.tmpDir)
	for _, e := range tmps {
		if strings.HasPrefix(e.Name(), "ingest-") {
			t.Errorf("tmpfs residue after oversize: %q", e.Name())
		}
	}
}

// --- ErrNoOwnerPasswords ----------------------------------------------------

func TestIngest_NoOwnerPasswords(t *testing.T) {
	s := newSetup(t)
	// Remove the seeded password.
	if err := s.idx.DeleteBackupPassword(s.pwID); err != nil {
		t.Fatal(err)
	}
	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 0))
	_, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrNoOwnerPasswords) {
		t.Fatalf("err = %v, want ErrNoOwnerPasswords", err)
	}
}

// --- unknown owner -----------------------------------------------------------

func TestIngest_UnknownOwner(t *testing.T) {
	s := newSetup(t)
	blob := buildSyntheticBackup(t, s.pw, buildMinimalZip(t, 15, 0))
	_, err := s.svc.IngestReader("NO_SUCH_OWNER", SourceInbox, "x.tryst", bytes.NewReader(blob))
	if !errors.Is(err, ErrUnknownOwner) {
		t.Fatalf("err = %v, want ErrUnknownOwner", err)
	}
}

// --- N15: log scrape --------------------------------------------------------
//
// A full happy-path ingest of a real-content backup must leave NO traces of
// content in the logs — no password, no encounter values, no partner names.

func TestIngest_LogsCarryNoContent(t *testing.T) {
	s := newSetup(t)
	// Build a backup whose data.json contains sentinel strings that a naive
	// logger would echo. If any of them appears in the logs, the test fails.
	const passwordSentinel = "SENTINEL_PASSWORD_correct-horse"
	const partnerSentinel = "SENTINEL_PARTNER_Jamie"
	const noteSentinel = "SENTINEL_NOTE_a_private_note"

	// Reset owner + password to use the password sentinel.
	if err := s.idx.DeleteBackupPassword(s.pwID); err != nil {
		t.Fatal(err)
	}
	if err := s.idx.AddBackupPassword(index.BackupPassword{
		ID: "PW2", OwnerID: s.ownerID, Label: "l",
		Passphrase: []byte(passwordSentinel), AddedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}

	dataJSON := `{
	  "schemaVersion": 15,
	  "tables": {
	    "partners":   [{"id":1,"name":"` + partnerSentinel + `"}],
	    "encounters": [{"id":1,"note":"` + noteSentinel + `"}]
	  }
	}`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(trystbk.EntryDataJSON)
	f.Write([]byte(dataJSON))
	_ = zw.Close()

	blob := buildSyntheticBackup(t, passwordSentinel, buf.Bytes())
	if _, err := s.svc.IngestReader(s.ownerID, SourceInbox, "x.tryst",
		bytes.NewReader(blob)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	logstr := s.logs.String()
	for _, sentinel := range []string{passwordSentinel, partnerSentinel, noteSentinel} {
		if strings.Contains(logstr, sentinel) {
			t.Errorf("N15 violation: log contains %q\nfull log:\n%s", sentinel, logstr)
		}
	}
	// Also scrape the event log: `event.detail` must be neutral.
	var details string
	rows, err := s.idx.DB().Query(`SELECT COALESCE(detail,'') FROM event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		_ = rows.Scan(&d)
		details += d + "\n"
	}
	for _, sentinel := range []string{passwordSentinel, partnerSentinel, noteSentinel} {
		if strings.Contains(details, sentinel) {
			t.Errorf("N15 violation: event.detail contains %q\ndetails:\n%s", sentinel, details)
		}
	}
}

// --- helpers ----------------------------------------------------------------

func assertEventLogged(t *testing.T, idx *index.Index, kind, reasonFragment string) {
	t.Helper()
	rows, err := idx.DB().Query(
		`SELECT COALESCE(detail,'') FROM event WHERE kind = ? ORDER BY id DESC`, kind)
	if err != nil {
		t.Fatalf("event query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(d, reasonFragment) {
			return
		}
	}
	t.Errorf("no event with kind=%q containing reason=%q", kind, reasonFragment)
}

// D09: only one ingest may stage at a time; a browser upload is refused
// immediately instead of piling a second 512 MiB file onto the tmpfs.
func TestIngestReader_UploadRefusedWhileAnotherIngestRuns_D09(t *testing.T) {
	s := newSetup(t)
	s.svc.stageSem <- struct{}{} // simulate an ingest in flight
	_, err := s.svc.IngestReader(s.ownerID, SourceUpload, "x.tryst", bytes.NewReader([]byte("x")))
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	<-s.svc.stageSem
	_, err = s.svc.IngestReader(s.ownerID, SourceUpload, "x.tryst", bytes.NewReader([]byte("x")))
	if errors.Is(err, ErrBusy) {
		t.Fatal("slot was released but upload still reports busy")
	}
}
