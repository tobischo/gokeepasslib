package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"errors"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
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

func TestDecodeFileGroupFirst31(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx3/group-first.kdbx", interopPassword)
	assertInteropContent(t, db)
}

func TestDecodeFileProtectedBinary31(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx3/protected-binary.kdbx", interopPassword)
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
	db2.Credentials = NewPasswordCredentials(interopPassword)
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

func TestDecodeFileProtectedBinary4(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx4/protected-binary.kdbx", interopPassword)
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
	cases := []struct {
		title   string
		xmlData string
	}{
		{
			// A child that genuinely cannot be parsed must surface an error
			// instead of being silently dropped, which would corrupt all
			// later protected values
			title:   "unparseable child",
			xmlData: "<Group><Entry><IconID>x</IconID></Entry></Group>",
		},
		{
			// Reading a token used to only stop at io.EOF, while the xml
			// decoder keeps returning a syntax error once it hit one,
			// which turned malformed input into an endless loop
			title:   "malformed xml",
			xmlData: "<Group><Entry></Group>",
		},
		{
			title:   "unparseable element of a child group",
			xmlData: "<Group><Group><IconID>x</IconID></Group></Group>",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var g Group

			if err := xml.Unmarshal([]byte(c.xmlData), &g); err == nil {
				t.Errorf("Expected an error, received nil")
			}
		})
	}

	// Unknown elements have to stay ignored, so that files written by a newer
	// version of KeePass can still be read
	var g Group
	if err := xml.Unmarshal(
		[]byte("<Group><Name>a</Name><SomethingNew>x</SomethingNew></Group>"),
		&g,
	); err != nil {
		t.Errorf("Expected unknown elements to be ignored, received: %s", err)
	}
}

func TestBinaryGetContentBytes(t *testing.T) {
	protected := w.NewBoolWrapper(true)

	cases := []struct {
		title    string
		binary   Binary
		expected []byte
	}{
		{
			// The decoded length has to be used, a padded base64 value would
			// otherwise return trailing zero bytes
			title:    "uncompressed base64 content with padding",
			binary:   Binary{Content: []byte("SGVsbG8=")},
			expected: []byte("Hello"),
		},
		{
			title:    "uncompressed base64 content without padding",
			binary:   Binary{Content: []byte("SGVsbG8xMg==")},
			expected: []byte("Hello12"),
		},
		{
			// KeePass ignores the Compressed flag of a protected binary
			title: "protected content is never compressed",
			binary: Binary{
				Content:    []byte("SGVsbG8="),
				Compressed: w.NewBoolWrapper(true),
				Protected:  &protected,
			},
			expected: []byte("Hello"),
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			data, err := c.binary.GetContentBytes()
			if err != nil {
				t.Fatalf("Failed to get content bytes: %s", err)
			}

			if !bytes.Equal(data, c.expected) {
				t.Errorf("Expected % x, received % x", c.expected, data)
			}
		})
	}
}

func TestProtectedBinaryInvalidContent(t *testing.T) {
	protected := w.NewBoolWrapper(true)

	newDatabase := func() *Database {
		db := NewDatabase()
		db.Credentials = NewPasswordCredentials(password)
		db.Content.Meta.Binaries = Binaries{
			{
				ID:        0,
				Content:   []byte("this is not base64!"),
				Protected: &protected,
			},
		}

		return db
	}

	// Locking or unlocking content which is not valid base64 has to fail
	// instead of skipping the binary, which would take the wrong amount of
	// bytes from the inner stream cipher and corrupt every protected value
	// that follows it
	if err := newDatabase().UnlockProtectedEntries(); !errors.Is(err, ErrInvalidProtectedBinary) {
		t.Errorf("Expected an ErrInvalidProtectedBinary while unlocking, received %v", err)
	}

	if err := newDatabase().LockProtectedEntries(); !errors.Is(err, ErrInvalidProtectedBinary) {
		t.Errorf("Expected an ErrInvalidProtectedBinary while locking, received %v", err)
	}
}

// TestUnprotectedBinariesKeepNoProtectedAttribute ensures that binaries which
// are not stream protected are written without a Protected attribute
func TestUnprotectedBinariesKeepNoProtectedAttribute(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx3/example.kdbx", examplePassword)

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}

	if len(db.Content.Meta.Binaries) == 0 {
		t.Fatalf("Expected the example file to contain a meta binary")
	}

	content, err := db.marshalXMLContent()
	if err != nil {
		t.Fatalf("Failed to marshal the database content: %s", err)
	}

	// Reading the written XML again shows whether the attribute was written:
	// it is only set if the element carries it
	var written DBContent
	if err := xml.Unmarshal(content, &written); err != nil {
		t.Fatalf("Failed to unmarshal the written content: %s", err)
	}

	if len(written.Meta.Binaries) != len(db.Content.Meta.Binaries) {
		t.Fatalf(
			"Expected %d meta binaries, received %d",
			len(db.Content.Meta.Binaries),
			len(written.Meta.Binaries),
		)
	}

	for _, binary := range written.Meta.Binaries {
		if binary.Protected != nil {
			t.Errorf(
				"Expected binary %d to be written without a Protected attribute",
				binary.ID,
			)
		}
	}
}
