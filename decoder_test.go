package gokeepasslib

import (
	"os"
	"testing"
)

func TestDecodeFile(t *testing.T) {
	file, err := os.Open("example.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}

	db := NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	db.UnlockProtectedEntries()
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].Password
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	f, err := os.Create("tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	enc := NewEncoder(f)
	enc.Encode(db)
}
