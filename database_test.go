package gokeepasslib

import (
	"bytes"
	"log"
	"reflect"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	cases := []struct {
		title            string
		options          []DatabaseOption
		expectedDatabase *Database
	}{
		{
			title: "without options",
			expectedDatabase: &Database{
				Options: &DBOptions{
					ValidateHashes: true,
				},
			},
		},
		{
			title: "with multiple options",
			options: []DatabaseOption{
				WithDatabaseFormattedTime(false),
				func(c *Database) {
					c.Options.ValidateHashes = false
				},
			},
			expectedDatabase: &Database{
				Options: &DBOptions{
					ValidateHashes: false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			database := NewDatabase(c.options...)

			if database.Options.ValidateHashes != c.expectedDatabase.Options.ValidateHashes {
				t.Errorf(
					"Did not receive expected database %+v, received %+v",
					database.Options.ValidateHashes,
					c.expectedDatabase.Options.ValidateHashes,
				)
			}
		})
	}
}

func TestDatabase_GetStreamManager(t *testing.T) {
	cases := []struct {
		title           string
		database        *Database
		expectedManager *StreamManager
		expectedErr     error
	}{
		{
			title:           "when db header is empty",
			database:        &Database{},
			expectedManager: nil,
			expectedErr:     nil,
		},
		{
			title: "when header FileHeaders is empty",
			database: &Database{
				Header: &DBHeader{},
			},
			expectedManager: nil,
			expectedErr:     nil,
		},
		{
			title: "when db content is empty (kdbx4)",
			database: &Database{
				Header: &DBHeader{
					Signature: &Signature{
						MajorVersion: 4,
					},
				},
			},
			expectedManager: nil,
			expectedErr:     ErrInvalidDatabaseOrCredentials,
		},
		{
			title: "when content InnerHeader is empty (kdbx4)",
			database: &Database{
				Header: &DBHeader{
					Signature: &Signature{
						MajorVersion: 4,
					},
				},
				Content: &DBContent{},
			},
			expectedManager: nil,
			expectedErr:     ErrInvalidDatabaseOrCredentials,
		},
		{
			title: "when content InnerHeader.InnerRandomStreamKey is empty (kdbx4)",
			database: &Database{
				Header: &DBHeader{
					Signature: &Signature{
						MajorVersion: 4,
					},
				},
				Content: &DBContent{
					InnerHeader: &InnerHeader{
						InnerRandomStreamKey: nil,
					},
				},
			},
			expectedManager: nil,
			expectedErr:     ErrInvalidDatabaseOrCredentials,
		},
		{
			title: "when header FileHeaders.ProtectedStreamKey is empty (kdbx3)",
			database: &Database{
				Header: &DBHeader{
					Signature: &Signature{
						MajorVersion: 3,
					},
					FileHeaders: &FileHeaders{
						ProtectedStreamKey: nil,
					},
				},
			},
			expectedManager: nil,
			expectedErr:     ErrInvalidDatabaseOrCredentials,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			manager, err := c.database.GetStreamManager()

			if !reflect.DeepEqual(manager, c.expectedManager) {
				t.Fatalf("Expected %v, received %v", c.expectedErr, err)
			}

			if err != c.expectedErr {
				t.Fatalf("Expected %v, received %v", c.expectedErr, err)
			}
		})
	}
}

func ExampleNewDatabase_kdbxv3() {
	buf := bytes.NewBuffer([]byte{})

	// create the new database
	db := NewDatabase(
		WithDatabaseKDBXVersion3(),
	)
	db.Content.Meta.DatabaseName = "KDBX4"
	db.Credentials = NewPasswordCredentials("supersecret")

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	// and encode it into the file
	keepassEncoder := NewEncoder(buf)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file to buffer")
}

func ExampleNewDatabase_kdbxv4() {
	buf := bytes.NewBuffer([]byte{})

	// create the new database
	db := NewDatabase(
		WithDatabaseKDBXVersion4(),
	)
	db.Content.Meta.DatabaseName = "KDBX4"
	db.Credentials = NewPasswordCredentials("supersecret")

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	// and encode it into the file
	keepassEncoder := NewEncoder(buf)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file to buffer")
}
