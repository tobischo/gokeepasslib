package gokeepasslib

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestDecodeFile(t *testing.T) {
	cases := []struct {
		title          string
		dbFilePath     string
		newCredentials func() (*DBCredentials, error)
	}{
		{
			title:      "Database Format v3.1, password credentials",
			dbFilePath: "tests/kdbx3/example.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
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
		},
		{
			title:      "Database Format v3.1, password+keydata credentials",
			dbFilePath: "tests/kdbx3/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				file, err := os.Open("tests/kdbx3/example-key.key")
				var keyData []byte
				if keyData, err = ioutil.ReadAll(file); err != nil {
					return nil, nil
				}

				return NewPasswordAndKeyDataCredentials(
					"abcdefg12345678",
					keyData,
				)
			},
		},
		{
			title:      "Database Format v4, password credentials",
			dbFilePath: "tests/kdbx4/example.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
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
		},
		{
			title:      "Database Format v4, password+keydata credentials",
			dbFilePath: "tests/kdbx4/example-key.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				file, err := os.Open("tests/kdbx4/example-key.key")
				var keyData []byte
				if keyData, err = ioutil.ReadAll(file); err != nil {
					return nil, nil
				}

				return NewPasswordAndKeyDataCredentials(
					"abcdefg12345678",
					keyData,
				)
			},
		},
		{
			title:      "Database Format v4, without compression, password credentials",
			dbFilePath: "tests/kdbx4/example-nocompression.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
		},
		{
			title:      "Database Format v4, chacha encryption, password credentials",
			dbFilePath: "tests/kdbx4/example-chacha.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
		},
		{
			title:      "Database Format v4, chacha encryption, argon2 key transformation, password credentials",
			dbFilePath: "tests/kdbx4/example-chacha-argon2.kdbx",
			newCredentials: func() (*DBCredentials, error) {
				return NewPasswordCredentials("abcdefg12345678"), nil
			},
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
			if pw != "Password" {
				t.Fatalf(
					"Failed to decode password: should be 'Password' not '%s'",
					pw,
				)
			}

			// Test secondary password matching
			pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
			if pw != "AnotherPassword" {
				t.Fatalf(
					"Failed to decode password: should be 'AnotherPassword' not '%s'",
					pw,
				)
			}
		})
	}
}
