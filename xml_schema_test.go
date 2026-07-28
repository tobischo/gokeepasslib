package gokeepasslib

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// schemaPath is the KDBX 4.1 XML schema as published on
// https://keepass.info/help/download/KDBX_XML.xsd
const schemaPath = "tests/KDBX_XML.xsd"

// prepareSchema returns the path to a copy of the KDBX XML schema which libxml2
// is able to compile.
//
// The published schema expresses the color pattern using the unicode escape
// sequence for the number sign, which libxml2 rejects, so it is replaced by the
// character it stands for.
func prepareSchema(t *testing.T) string {
	t.Helper()

	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("Failed to read the KDBX XML schema: %s", err)
	}

	schema = bytes.ReplaceAll(schema, []byte("\\u0023"), []byte("#"))

	return writeTempFile(t, "*.xsd", schema)
}

// writeTempFile writes the given content into a new file in the temporary
// directory of the test and returns its path
func writeTempFile(t *testing.T, pattern string, content []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		t.Fatalf("Failed to write temporary file: %s", err)
	}

	return file.Name()
}

// validateAgainstSchema validates the given XML document against the KDBX XML
// schema using xmllint
func validateAgainstSchema(t *testing.T, schema string, document []byte) {
	t.Helper()

	path := writeTempFile(t, "*.xml", document)

	cmd := exec.CommandContext(
		t.Context(),
		"xmllint", "--noout", "--schema", schema, path,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf(
			"Encoded XML does not match the KDBX XML schema:\n%s",
			strings.TrimSpace(string(output)),
		)
	}
}

// encodedXMLContent returns the XML document which would be written into a KDBX
// file for the given database
func encodedXMLContent(t *testing.T, db *Database) []byte {
	t.Helper()

	// The encoder expects the protected values of the database to be locked
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Failed to lock protected entries: %s", err)
	}

	// Encoding prepares the content of the database, e.g. it locks the protected
	// values and ensures that the file format version fits the content
	if err := NewEncoder(io.Discard).Encode(db); err != nil {
		t.Fatalf("Failed to encode database: %s", err)
	}

	content, err := db.marshalXMLContent()
	if err != nil {
		t.Fatalf("Failed to marshal the database content: %s", err)
	}

	return content
}

// TestEncodedXMLMatchesSchema ensures that the XML written by the encoder is
// valid according to the KDBX XML schema for every supported format version
func TestEncodedXMLMatchesSchema(t *testing.T) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint is not available")
	}

	schema := prepareSchema(t)

	cases := []struct {
		title string
		db    func(t *testing.T) *Database
	}{
		{
			title: "KDBX 3.1 example file",
			db: func(t *testing.T) *Database {
				return decodeExampleDatabase(t, "tests/kdbx3/example.kdbx")
			},
		},
		{
			title: "KDBX 4.0 example file",
			db: func(t *testing.T) *Database {
				return decodeExampleDatabase(t, "tests/kdbx4/example.kdbx")
			},
		},
		{
			title: "KDBX 4.1 example file",
			db: func(t *testing.T) *Database {
				return decodeExampleDatabase(t, "tests/kdbx41/example.kdbx")
			},
		},
		{
			title: "KDBX 3.1 database with all supported elements",
			db: func(t *testing.T) *Database {
				return databaseWithAllElements(t, WithDatabaseKDBXVersion3())
			},
		},
		{
			title: "KDBX 4.0 database with all supported elements",
			db: func(t *testing.T) *Database {
				return databaseWithAllElements(t, WithDatabaseKDBXVersion40())
			},
		},
		{
			title: "KDBX 4.1 database with all supported elements",
			db: func(t *testing.T) *Database {
				return databaseWithAllElements(t, WithDatabaseKDBXVersion41())
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			validateAgainstSchema(t, schema, encodedXMLContent(t, c.db(t)))
		})
	}
}

// kdbx41Elements counts the elements which were introduced in KDBX 4.1.
//
// The published schema only covers the newest file format version, so it accepts
// those elements in a KDBX 3.1 or KDBX 4.0 document as well. They are therefore
// checked separately.
var kdbx41Elements = map[string]string{
	fieldGroupTags:                      "count(//Group/Tags)",
	fieldGroupPreviousParentGroup:       "count(//Group/PreviousParentGroup)",
	fieldEntryPreviousParentGroup:       "count(//Entry/PreviousParentGroup)",
	fieldEntryQualityCheck:              "count(//Entry/QualityCheck)",
	fieldCustomIconName:                 "count(//Icon/Name)",
	fieldCustomIconLastModificationTime: "count(//Icon/LastModificationTime)",
	fieldCustomDataLastModificationTime: "count(//CustomData/Item/LastModificationTime)",
}

// countElements evaluates the given XPath count expression against the given
// XML document
func countElements(t *testing.T, document []byte, xpath string) int {
	t.Helper()

	path := writeTempFile(t, "*.xml", document)

	cmd := exec.CommandContext(t.Context(), "xmllint", "--xpath", xpath, path)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to evaluate '%s': %s", xpath, strings.TrimSpace(string(output)))
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("Failed to parse the result of '%s': %s", xpath, err)
	}

	return count
}

// TestKDBX41ElementsAreVersionDependent ensures that the elements which were
// introduced in KDBX 4.1 are only written into KDBX 4.1 files
func TestKDBX41ElementsAreVersionDependent(t *testing.T) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint is not available")
	}

	cases := []struct {
		title    string
		option   DatabaseOption
		expected bool
	}{
		{
			title:  "KDBX 3.1",
			option: WithDatabaseKDBXVersion3(),
		},
		{
			title:  "KDBX 4.0",
			option: WithDatabaseKDBXVersion40(),
		},
		{
			title:    "KDBX 4.1",
			option:   WithDatabaseKDBXVersion41(),
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			document := encodedXMLContent(t, databaseWithAllElements(t, c.option))

			for name, xpath := range kdbx41Elements {
				count := countElements(t, document, xpath)

				if c.expected && count == 0 {
					t.Errorf("Expected %s to be written, received no element", name)
				}

				if !c.expected && count != 0 {
					t.Errorf("Expected %s not to be written, received %d", name, count)
				}
			}
		})
	}
}

func decodeExampleDatabase(t *testing.T, path string) *Database {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	db := NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")

	if err := NewDecoder(file).Decode(db); err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock protected entries: %s", err)
	}

	return db
}
