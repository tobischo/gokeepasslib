package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"os"
	"testing"
)

// The tests/kdbx3/group-first.kdbx and tests/kdbx*/protected-binary.kdbx
// fixtures were generated with kdbxweb 1.14.4, master password "123".
//
// Content: entries "e1-root" (password "PASS-e1-v2", one history state with
// password "PASS-e1"), "e4-root" (password "PASS-e4", protected custom field
// otp=JBSWY3DPEHPK3PXP), "e5-empty" (empty password), group "g1" with
// "e2-in-g1" (password "PASS-e2", attachment a.bin = 16 x 0x07 stored as a
// stream-protected binary in the protected-binary fixtures) and nested
// group "g2" with "e3-in-g2" (password "PASS-e3").
//
// The files serialize child groups before entries and, on KDBX v3.1, store
// the attachment as `<Binary Protected="True">` in the Meta section, where
// it consumes the inner stream cipher before any entry value does.

func decodeInteropFixture(t *testing.T, path string) *Database {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	db := NewDatabase()
	db.Credentials = NewPasswordCredentials("123")
	if err := NewDecoder(file).Decode(db); err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}
	return db
}

func findEntryByTitle(gs []Group, title string) *Entry {
	for i := range gs {
		for j := range gs[i].Entries {
			if gs[i].Entries[j].GetTitle() == title {
				return &gs[i].Entries[j]
			}
		}
		if e := findEntryByTitle(gs[i].Groups, title); e != nil {
			return e
		}
	}
	return nil
}

func assertInteropContent(t *testing.T, db *Database) {
	t.Helper()

	expected := map[string]string{
		"e1-root":  "PASS-e1-v2",
		"e2-in-g1": "PASS-e2",
		"e3-in-g2": "PASS-e3",
		"e4-root":  "PASS-e4",
		"e5-empty": "",
	}
	for title, want := range expected {
		entry := findEntryByTitle(db.Content.Root.Groups, title)
		if entry == nil {
			t.Fatalf("Entry %q not found", title)
		}
		if got := entry.GetPassword(); got != want {
			t.Errorf("Entry %q: expected password %q, received %q", title, want, got)
		}
	}

	e1 := findEntryByTitle(db.Content.Root.Groups, "e1-root")
	if len(e1.Histories) == 0 || len(e1.Histories[0].Entries) == 0 {
		t.Fatalf("Entry e1-root: expected one history entry")
	}
	if got := e1.Histories[0].Entries[0].GetPassword(); got != "PASS-e1" {
		t.Errorf("Entry e1-root history: expected password %q, received %q", "PASS-e1", got)
	}

	e4 := findEntryByTitle(db.Content.Root.Groups, "e4-root")
	if got := e4.GetContent("otp"); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Entry e4-root: expected otp %q, received %q", "JBSWY3DPEHPK3PXP", got)
	}
}

func TestDecodeFile_GroupFirst31(t *testing.T) {
	db := decodeInteropFixture(t, "tests/kdbx3/group-first.kdbx")
	assertInteropContent(t, db)
}

func TestDecodeFile_ProtectedBinary31(t *testing.T) {
	db := decodeInteropFixture(t, "tests/kdbx3/protected-binary.kdbx")
	assertInteropContent(t, db)

	wantBinary := bytes.Repeat([]byte{0x07}, 16)

	binary := db.Content.Meta.Binaries.Find(0)
	if binary == nil {
		t.Fatalf("Expected meta binary with ID 0")
	}
	if !binary.isStreamProtected() {
		t.Errorf("Expected meta binary to have Protected=True")
	}
	data, err := binary.GetContentBytes()
	if err != nil {
		t.Fatalf("Failed to read protected binary content: %s", err)
	}
	if !bytes.Equal(data, wantBinary) {
		t.Errorf("Protected binary content: expected % x, received % x", wantBinary, data)
	}

	// Round-trip: locking, encoding and decoding again must keep all
	// protected values and the protected binary intact.
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}
	var buf bytes.Buffer
	if err := NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Failed to encode file: %s", err)
	}

	db2 := NewDatabase()
	db2.Credentials = NewPasswordCredentials("123")
	if err := NewDecoder(bytes.NewReader(buf.Bytes())).Decode(db2); err != nil {
		t.Fatalf("Failed to decode re-encoded file: %s", err)
	}
	if err := db2.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Problem unlocking re-encoded entries. %s", err)
	}
	assertInteropContent(t, db2)

	binary2 := db2.Content.Meta.Binaries.Find(0)
	if binary2 == nil {
		t.Fatalf("Expected meta binary with ID 0 after round-trip")
	}
	if !binary2.isStreamProtected() {
		t.Errorf("Expected Protected=True to survive the round-trip")
	}
	data2, err := binary2.GetContentBytes()
	if err != nil {
		t.Fatalf("Failed to read protected binary content after round-trip: %s", err)
	}
	if !bytes.Equal(data2, wantBinary) {
		t.Errorf("Protected binary content after round-trip: expected % x, received % x",
			wantBinary, data2)
	}
}

func TestDecodeFile_ProtectedBinary4(t *testing.T) {
	db := decodeInteropFixture(t, "tests/kdbx4/protected-binary.kdbx")
	assertInteropContent(t, db)

	binary := db.Content.InnerHeader.Binaries.Find(0)
	if binary == nil {
		t.Fatalf("Expected inner header binary with ID 0")
	}
	data, err := binary.GetContentBytes()
	if err != nil {
		t.Fatalf("Failed to read binary content: %s", err)
	}
	if want := bytes.Repeat([]byte{0x07}, 16); !bytes.Equal(data, want) {
		t.Errorf("Binary content: expected % x, received % x", want, data)
	}
}

func TestGroupUnmarshalPropagatesChildErrors(t *testing.T) {
	// A child that genuinely cannot be parsed must surface an error instead of
	// being silently dropped (which would corrupt all later protected values).
	var g Group
	err := xml.Unmarshal([]byte("<Group><Entry><IconID>x</IconID></Entry></Group>"), &g)
	if err == nil {
		t.Fatalf("Expected an error for unparseable entry, received nil (silent drop)")
	}
}
