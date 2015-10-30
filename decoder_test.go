package gokeepasslib

import (
	"os"
	"testing"
)

func TestDecodeFile(t *testing.T) {
	file, err := os.Open("examples/example.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	db := new(Database)
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	//Tests out the binary file in example.kdbx
	binary := db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Find(db.Content.Meta.Binaries)
	if binary == nil {
		t.Fatalf("Failed to find binary")
	}
	str, err := binary.GetContent()
	if err != nil {
		t.Fatal("Error getting content from binary: ", err, str)
	}
	if str != "Hello world" {
		t.Fatalf("Binary content was not as expected, expected: `Hello world`, received `%s`", str)
	}

	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Also properly decoded the second entry
	pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
	if string(pw) != "AnotherPassword" {
		t.Fatalf(
			"Failed to decode password: should be 'AnotherPassword' not '%s'",
			pw,
		)
	}

	f, err := os.Create("examples/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	//Changes the value of a entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = "http://github.com"

	err = db.LockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}

	enc := NewEncoder(f)
	err = enc.Encode(db)
	if err != nil {
		t.Fatalf("Failed to encode file: %s", err)
	}

	tmpfile, err := os.Open("examples/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer tmpfile.Close()

	db = new(Database)
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(tmpfile).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}
	pw = db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != "http://github.com" {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}
}

func TestCreateNewFile(t *testing.T) {
	//Creates a brand new kdbx file using only the library
	newdb := NewDatabase()

	if newdb.Content.Root.Groups[0].Entries[0].GetTitle() != "Sample Entry" {
		t.Fatalf("NewRootData() seemed to not work, title should be 'Sample Entry', was %s", newdb.Content.Root.Groups[0].Entries[0].GetTitle())
	}

	newdb.Credentials = NewPasswordCredentials("password")

	err := newdb.LockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}

	newfile, err := os.Create("examples/new.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	newencoder := NewEncoder(newfile)
	err = newencoder.Encode(newdb)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Please open example/new.kdbx with keepass2 to verify that it works")
}
