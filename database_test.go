package gokeepasslib

import (
	"bytes"
	"log"
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
