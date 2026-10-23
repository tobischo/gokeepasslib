package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"testing"
)

func TestDecodeFile(t *testing.T) {
	cases := []struct {
		title          string
		dbFilePath     string
		newCredentials func() (*DBCredentials, error)
		testContent    bool
	}{
		{
			title:      "Database Format v3.1, password credentials",
			dbFilePath: "tests/kdbx3/example.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title:      "Database Format v3.1, password+key credentials",
			dbFilePath: "tests/kdbx3/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordAndKeyCredentials(
					"abcdefg12345678",
					"tests/kdbx3/example-key.key",
				)
			},
			testContent: true,
		},
		{
			title:      "Database Format v3.1, password+keydata credentials",
			dbFilePath: "tests/kdbx3/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				file, err := os.Open("tests/kdbx3/example-key.key")
				if err != nil {
					return nil, err
				}

				var keyData []byte
				if keyData, err = io.ReadAll(file); err != nil {
					return nil, err
				}

				return NewPasswordAndKeyDataCredentials(
					"abcdefg12345678",
					keyData,
				)
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, password credentials",
			dbFilePath: "tests/kdbx4/example.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, password+key credentials",
			dbFilePath: "tests/kdbx4/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordAndKeyCredentials(
					"abcdefg12345678",
					"tests/kdbx4/example-key.key",
				)
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, password+keydata credentials",
			dbFilePath: "tests/kdbx4/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				file, err := os.Open("tests/kdbx4/example-key.key")
				if err != nil {
					return nil, err
				}

				var keyData []byte
				if keyData, err = io.ReadAll(file); err != nil {
					return nil, err
				}

				return NewPasswordAndKeyDataCredentials(
					"abcdefg12345678",
					keyData,
				)
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, without compression, password credentials",
			dbFilePath: "tests/kdbx4/example-nocompression.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, chacha encryption, password credentials",
			dbFilePath: "tests/kdbx4/example-chacha.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title: "Database Format v4, chacha encryption, " +
				"argon2 key transformation, password credentials",
			dbFilePath: "tests/kdbx4/example-chacha-argon2.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title:      "Database Format v4.1, password credentials",
			dbFilePath: "tests/kdbx41/example.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
			testContent: true,
		},
		{
			title:      "Database Format v4, twofish encryption, password credentials",
			dbFilePath: "tests/kdbx4/example-twofish.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("test1234test"), nil
			},
			testContent: false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			// Open file
			file, err := os.Open(c.dbFilePath)
			if err != nil {
				t.Fatalf("Failed to open keepass file: %s", err)
			}
			defer file.Close()

			// Decode database
			db := NewDatabase()
			credentials, err := c.newCredentials()
			if err != nil {
				t.Fatalf("Failed to build new credentials: %+v", err)
			}
			db.Credentials = credentials
			err = NewDecoder(file).Decode(db)
			if err != nil {
				t.Fatalf("Failed to decode file: %s", err)
			}

			if !c.testContent {
				return
			}

			// Test binary file matching
			binary := db.FindBinary(db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Value.ID)
			if binary == nil {
				t.Fatalf("Failed to find binary")
			}
			str, err := binary.GetContentString()
			if err != nil {
				t.Fatal("Error getting content from binary: ", err, str)
			}
			if str != "Hello world" {
				t.Fatalf("Binary content was not as expected, expected: `Hello world`, received `%s`", str)
			}

			// Unlock entries
			err = db.UnlockProtectedEntries()
			if err != nil {
				t.Fatalf("Problem unlocking entries. %s", err)
			}

			// Test password matching
			pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
			if pw != password {
				t.Fatalf(
					"Failed to decode password: should be 'Password' not '%s'",
					pw,
				)
			}

			// Test secondary password matching
			pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
			if pw != anotherPassword {
				t.Fatalf(
					"Failed to decode password: should be 'AnotherPassword' not '%s'",
					pw,
				)
			}
		})
	}
}

func TestDecodeTruncatedFile(t *testing.T) {
	cases := []struct {
		title      string
		dbFilePath string
		// Bytes at the end which are never read, e.g. the additional empty
		// KDBX v4 block which is written by this library
		unreadBytes int
	}{
		{
			title:      "Database Format v3.1",
			dbFilePath: "tests/kdbx3/example.kdbx",
		},
		{
			title:      "Database Format v4",
			dbFilePath: "tests/kdbx4/example.kdbx",
		},
		{
			title:      "Database Format v4, chacha encryption",
			dbFilePath: "tests/kdbx4/example-chacha.kdbx",
		},
		{
			title:      "Database Format v4, twofish encryption",
			dbFilePath: "tests/kdbx4/example-twofish.kdbx",
		},
		{
			title:       "Database Format v4.1",
			dbFilePath:  "tests/kdbx41/example.kdbx",
			unreadBytes: 36,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			data, err := os.ReadFile(c.dbFilePath)
			if err != nil {
				t.Fatalf("Failed to read file: %s", err)
			}

			end := len(data) - c.unreadBytes
			sizes := []int{
				0, 1, 12, len(data) / 2,
				end - 1, end - 4, end - 15, end - 16, end - 17, end - 40, end - 100,
			}

			for _, size := range sizes {
				db := NewDatabase()
				db.Credentials = NewPasswordCredentials(examplePassword)

				err := NewDecoder(bytes.NewReader(data[:size])).Decode(db)
				if err == nil {
					t.Fatalf("Expected an error for a file truncated to %d of %d bytes", size, len(data))
				}
			}
		})
	}
}

func TestDecodeRawContentTruncatedGzip(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion3())
	db.Credentials = NewPasswordCredentials(examplePassword)

	transformedKey, err := db.getTransformedKey()
	if err != nil {
		t.Fatalf("Failed to transform key: %s", err)
	}

	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	w.Write(xmlHeader)
	w.Close()

	// Encode the truncated gzip stream as is and decode it as compressed content
	db.Header.FileHeaders.CompressionFlags = NoCompressionFlag
	encoded, err := encodeRawContent(db, compressed.Bytes()[:compressed.Len()-4], transformedKey)
	if err != nil {
		t.Fatalf("Failed to encode content: %s", err)
	}
	db.Header.FileHeaders.CompressionFlags = GzipCompressionFlag

	err = decodeRawContent(db, encoded, transformedKey)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Received error '%v', expected '%v'", err, io.ErrUnexpectedEOF)
	}
}

func TestReadBytes(t *testing.T) {
	cases := []struct {
		title        string
		data         []byte
		length       int64
		expectedData []byte
		expectedErr  error
	}{
		{
			title:        "exact length",
			data:         []byte{0x01, 0x02, 0x03},
			length:       3,
			expectedData: []byte{0x01, 0x02, 0x03},
		},
		{
			title:        "shorter length",
			data:         []byte{0x01, 0x02, 0x03},
			length:       2,
			expectedData: []byte{0x01, 0x02},
		},
		{
			title:        "zero length",
			data:         []byte{0x01},
			length:       0,
			expectedData: []byte{},
		},
		{
			title:       "length beyond the data",
			data:        []byte{0x01, 0x02, 0x03},
			length:      0xffffffff,
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			title:       "negative length",
			data:        []byte{0x01, 0x02, 0x03},
			length:      -1,
			expectedErr: ErrCorruptedDatabase,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			data, err := readBytes(bytes.NewReader(c.data), c.length)
			if !errors.Is(err, c.expectedErr) {
				t.Fatalf("Received error '%v', expected '%v'", err, c.expectedErr)
			}
			if !bytes.Equal(data, c.expectedData) {
				t.Fatalf("Received data '% x', expected '% x'", data, c.expectedData)
			}
		})
	}
}

func TestDecodeRawContentInvalidEncryptionIV(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion3())
	db.Credentials = NewPasswordCredentials(examplePassword)

	transformedKey, err := db.getTransformedKey()
	if err != nil {
		t.Fatalf("Failed to transform key: %s", err)
	}

	encoded, err := encodeRawContent(db, xmlHeader, transformedKey)
	if err != nil {
		t.Fatalf("Failed to encode content: %s", err)
	}
	db.Header.FileHeaders.EncryptionIV = db.Header.FileHeaders.EncryptionIV[:8]

	err = decodeRawContent(db, encoded, transformedKey)
	if !errors.Is(err, ErrCorruptedDatabase) {
		t.Fatalf("Received error '%v', expected '%v'", err, ErrCorruptedDatabase)
	}
}
