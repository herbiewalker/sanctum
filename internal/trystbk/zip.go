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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Well-known errors from the ZIP inspection stage.
var (
	ErrBadZip            = errors.New("trystbk: decrypted body is not a well-formed ZIP")
	ErrNoDataJSON        = errors.New("trystbk: backup is missing data.json")
	ErrZipSlip           = errors.New("trystbk: ZIP entry name escapes the archive root")
	ErrDataJSONMalformed = errors.New("trystbk: data.json malformed or unexpected shape")
	ErrTooManyEntries    = errors.New("trystbk: ZIP has an unreasonable number of entries (zip bomb?)")
)

// maxZipEntries bounds how many entries we are willing to iterate over. A
// legitimate backup has one data.json plus one entry per media blob; even a
// user with tens of thousands of photos is far below this cap. A file with an
// order-of-magnitude more entries is either broken or a zip bomb (T6).
const maxZipEntries = 200_000

// inspectZip walks the decrypted body as a ZIP and produces a Manifest.
//
// It reads data.json (a small, known-shape JSON), records per-table row
// counts, and counts media entries FROM THE CENTRAL DIRECTORY ONLY (D-15).
// It does NOT call Open() on any entry under media/ — the guarantee in N19 is
// enforced here, at the one place where any code could break it.
func inspectZip(body []byte) (*Manifest, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadZip, err)
	}

	if len(zr.File) > maxZipEntries {
		return nil, fmt.Errorf("%w: %d", ErrTooManyEntries, len(zr.File))
	}

	m := &Manifest{TableCounts: map[string]int{}}
	var dataJSONFile *zip.File

	for _, f := range zr.File {
		// Zip-Slip validation on every name we encounter, even ones we do not
		// plan to extract, so a hostile name is a rejection here rather than
		// something a future maintainer accidentally trusts (N10).
		if err := validateEntryName(f.Name); err != nil {
			return nil, err
		}

		switch {
		case f.Name == EntryDataJSON:
			// Multiple data.json entries would be genuinely weird; keep the
			// first one and treat any duplicate as malformed. archive/zip
			// exposes them in file order, matching what would be extracted.
			if dataJSONFile != nil {
				return nil, fmt.Errorf("%w: multiple data.json entries", ErrDataJSONMalformed)
			}
			dataJSONFile = f

		case strings.HasPrefix(f.Name, EntryMediaPrefix):
			// D-15 / N19: metadata only. UncompressedSize64 comes from the
			// central-directory record; reading it does NOT decrypt the
			// entry's data payload. THE NEXT LINE MUST NEVER BECOME f.Open().
			m.TableCounts[SyntheticMediaKey]++
			m.MediaBytes += int64(f.UncompressedSize64)

		default:
			// Any other entry name is either format evolution we do not know
			// about or a hostile file. We tolerate it (unknown entries pass
			// through; DATA_MODEL says a vault must not refuse to hold a
			// newer backup) but do not read it.
		}
	}

	if dataJSONFile == nil {
		return nil, ErrNoDataJSON
	}

	if err := readDataJSON(dataJSONFile, m); err != nil {
		return nil, err
	}
	return m, nil
}

// validateEntryName rejects Zip-Slip and any absolute or traversal path. The
// resolved path must be a clean forward-slash-only relative path with no ".."
// component and no leading slash.
//
// We do NOT anchor against a target directory because Sanctum never writes any
// entry to the filesystem (D-15, and the whole D-5 approach). The check exists
// so that a future maintainer who DOES extract entries cannot do so unsafely
// by accident — the names have already been screened before they reach any
// filesystem code.
func validateEntryName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrZipSlip)
	}
	// Reject any backslashes, absolute paths, drive letters. These are
	// checked before path.Clean because Clean's behaviour on Windows-style
	// separators is not what we want here.
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("%w: backslash in %q", ErrZipSlip, name)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: absolute path %q", ErrZipSlip, name)
	}
	// path.Clean flattens "." and ".." components. Any remaining ".." (or a
	// name that Cleans to "..") is an escape attempt.
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: escapes root: %q", ErrZipSlip, name)
	}
	// Also reject rooted-after-clean, defence in depth.
	if path.IsAbs(cleaned) {
		return fmt.Errorf("%w: absolute after clean: %q", ErrZipSlip, name)
	}
	return nil
}

// readDataJSON opens data.json (this IS a decrypt of user data, but only the
// tables-of-metadata portion — no media, no photo bytes) and extracts:
//
//   - schemaVersion (an int)
//   - the row count of each table, computed by counting array elements in
//     tables.<name>[…] without materialising individual row objects.
//
// The plaintext of data.json exists in memory for the duration of this
// function only.
func readDataJSON(f *zip.File, m *Manifest) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("%w: open data.json: %v", ErrDataJSONMalformed, err)
	}
	defer rc.Close()

	// Bound data.json's size too. It is a JSON serialisation of the whole
	// database; even a large user's is well under 100 MiB. A crafted entry
	// that claimed a huge uncompressed size would already have been rejected
	// upstream by MaxBackupBytes, but bounding here means an isolated bad
	// entry cannot exhaust memory either.
	const maxDataJSONBytes = 128 << 20 // 128 MiB
	dec := json.NewDecoder(io.LimitReader(rc, maxDataJSONBytes+1))
	dec.UseNumber()

	if err := parseDataJSON(dec, m); err != nil {
		return fmt.Errorf("%w: %v", ErrDataJSONMalformed, err)
	}
	return nil
}

// parseDataJSON walks:  { "schemaVersion": N, "tables": { "<t>": [ …rows… ] } }
// without loading rows into memory. Row objects are streamed past via
// Decoder.Token, counting the "{" that open each element.
func parseDataJSON(dec *json.Decoder, m *Manifest) error {
	// Expect an object.
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		key, err := readObjectKey(dec)
		if err != nil {
			return err
		}
		switch key {
		case "schemaVersion":
			t, err := dec.Token()
			if err != nil {
				return err
			}
			num, ok := t.(json.Number)
			if !ok {
				return fmt.Errorf("schemaVersion is not a number: %T", t)
			}
			v, err := num.Int64()
			if err != nil {
				return fmt.Errorf("schemaVersion %q: %v", num, err)
			}
			m.TrystSchemaVersion = int(v)

		case "tables":
			if err := parseTablesObject(dec, m); err != nil {
				return err
			}

		default:
			// Unknown top-level key — a future Tryst may add ones we do not
			// know about. Skip its value without interpretation.
			if err := skipValue(dec); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return err
	}
	return nil
}

func parseTablesObject(dec *json.Decoder, m *Manifest) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tableName, err := readObjectKey(dec)
		if err != nil {
			return err
		}
		// Reserved synthetic names (e.g. our own __media__) must never appear
		// as a real Tryst table — if one does, refuse rather than merge with
		// our own bookkeeping.
		if strings.HasPrefix(tableName, "__") {
			return fmt.Errorf("unexpected reserved-shape table name %q", tableName)
		}
		count, err := countArrayElements(dec)
		if err != nil {
			return fmt.Errorf("counting table %q: %w", tableName, err)
		}
		m.TableCounts[tableName] = count
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return err
	}
	return nil
}

// countArrayElements consumes an array and returns the number of top-level
// elements, without holding any row's parsed value.
func countArrayElements(dec *json.Decoder) (int, error) {
	if err := expectDelim(dec, '['); err != nil {
		return 0, err
	}
	n := 0
	for dec.More() {
		if err := skipValue(dec); err != nil {
			return 0, err
		}
		n++
	}
	if _, err := dec.Token(); err != nil { // consume closing ']'
		return 0, err
	}
	return n, nil
}

// skipValue advances past the next value at any nesting depth without holding
// its contents. It uses Token to keep memory bounded by nesting depth, not by
// value size — the whole point of streaming past encounter rows.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

func readObjectKey(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	if err != nil {
		return "", err
	}
	s, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("expected string key, got %T", t)
	}
	return s, nil
}

func expectDelim(dec *json.Decoder, want rune) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok || rune(d) != want {
		return fmt.Errorf("expected %q, got %v", want, t)
	}
	return nil
}

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣
