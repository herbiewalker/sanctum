package trystbk

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
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// N10 / T6: every Zip-Slip shape must be rejected. Tested against the
// public entry-point so we exercise the validation exactly as ingest will.
func TestInspectZip_RejectsZipSlip(t *testing.T) {
	for _, name := range []string{
		"../escape.txt",
		"../../escape",
		"/absolute",
		`..\windows`,
		`sub\..\..\escape`,
	} {
		t.Run(name, func(t *testing.T) {
			body := buildZip(t, []zipEntry{
				{name: EntryDataJSON, body: minimalDataJSON(1)},
				{name: name, body: []byte("x")},
			})
			_, err := inspectZip(body)
			if !errors.Is(err, ErrZipSlip) {
				t.Fatalf("name=%q err = %v, want ErrZipSlip", name, err)
			}
		})
	}
}

// Names that are safe but nearby the slip patterns must NOT be rejected.
// A false positive here means a legitimate future format lands as an
// integrity failure, which is worse than a wide-open rule for our threat
// model (we do not extract these files anyway).
func TestInspectZip_AllowsBenignNames(t *testing.T) {
	cases := []struct {
		name string
		body []byte // nil for a directory entry
	}{
		{name: "a/b/c.txt", body: []byte("x")},
		{name: "deep/nested/entry", body: []byte("x")},
		{name: "trailing/", body: nil}, // directory entry — valid ZIP shape
		{name: "file.with.dots.txt", body: []byte("x")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := buildZip(t, []zipEntry{
				{name: EntryDataJSON, body: minimalDataJSON(1)},
				{name: c.name, body: c.body},
			})
			if _, err := inspectZip(body); err != nil {
				t.Fatalf("name=%q: unexpected err %v", c.name, err)
			}
		})
	}
}

// N19 / D-15: media entries must NEVER be opened. We prove it by writing a
// media entry with an unsupported compression method (99), registered only on
// the writer. archive/zip reads the entry's METADATA (name, uncompressed
// size) from the central directory just fine — but any call to f.Open()
// returns "unsupported compression algorithm" because the READER has no
// method-99 decompressor registered. If inspectZip succeeds, we did not call
// Open on the media entry. QED.
//
// The count and size assertions on the result also guard against the trivial
// false positive of inspectZip having no media in its input at all.
func TestInspectZip_DoesNotOpenMediaEntries(t *testing.T) {
	const declaredSize = 4096

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Register method 99 on the writer only. This is what makes CreateHeader
	// accept it; the reader will not have it, and Open() on any method-99
	// entry will return an error.
	zw.RegisterCompressor(99, func(w io.Writer) (io.WriteCloser, error) {
		return nopWriteCloser{w}, nil
	})

	f, err := zw.CreateHeader(&zip.FileHeader{Name: EntryDataJSON, Method: zip.Store})
	assertNoErr(t, err, "create data.json")
	_, err = f.Write(minimalDataJSON(1))
	assertNoErr(t, err, "write data.json")

	mf, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "media/poison.jpg",
		Method: 99, // unsupported by any default reader
	})
	assertNoErr(t, err, "create media entry")
	_, err = mf.Write(bytes.Repeat([]byte{0}, declaredSize))
	assertNoErr(t, err, "write media dummy")
	assertNoErr(t, zw.Close(), "zip close")

	m, err := inspectZip(buf.Bytes())
	if err != nil {
		t.Fatalf("inspectZip must succeed if we never opened media entries; got %v", err)
	}
	if m.TableCounts[SyntheticMediaKey] != 1 {
		t.Errorf("media count = %d, want 1", m.TableCounts[SyntheticMediaKey])
	}
	if m.MediaBytes != declaredSize {
		t.Errorf("MediaBytes = %d, want %d (central-directory declared)", m.MediaBytes, declaredSize)
	}

	// Belt-and-braces: manually attempt to Open+Read the poison entry, and
	// require it to fail. If this ever starts succeeding, archive/zip has
	// grown support for method 99 and this test's "we never Open()'d" proof
	// needs a new mechanism — the failure below is where the search starts.
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	assertNoErr(t, err, "reopen for verification")
	for _, e := range zr.File {
		if !strings.HasPrefix(e.Name, "media/") {
			continue
		}
		rc, openErr := e.Open()
		if openErr != nil {
			continue // expected — reader has no method-99 decompressor
		}
		_, readErr := rc.Read(make([]byte, 1))
		rc.Close()
		if readErr == nil {
			t.Fatal("archive/zip opened+read a method=99 entry; N19 proof mechanism needs revisiting")
		}
	}
}

// nopWriteCloser wraps an io.Writer so a zip.Writer.RegisterCompressor
// callback can satisfy the io.WriteCloser signature without actually
// compressing. It stores the bytes verbatim.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// A ZIP that is not a ZIP at all (or is truncated so badly the central
// directory cannot be found) fails as ErrBadZip, not as a panic.
func TestInspectZip_RejectsMalformedZip(t *testing.T) {
	if _, err := inspectZip([]byte("this is not a zip")); !errors.Is(err, ErrBadZip) {
		t.Fatalf("err = %v, want ErrBadZip", err)
	}
	if _, err := inspectZip(nil); !errors.Is(err, ErrBadZip) {
		t.Fatalf("nil body: err = %v, want ErrBadZip", err)
	}
}

// Empty ZIP (valid but no data.json) => ErrNoDataJSON.
func TestInspectZip_EmptyZip(t *testing.T) {
	body := buildZip(t, nil)
	if _, err := inspectZip(body); !errors.Is(err, ErrNoDataJSON) {
		t.Fatalf("err = %v, want ErrNoDataJSON", err)
	}
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
