package gokeepasslib

import (
	"os"
	"testing"
)

// Decode database v3.1
func TestDecodeFile31(t *testing.T) {
	// Open file
	file, err := os.Open("tests/kdbx3/example.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	// Decode database
	db := NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	// Test binary file matching
	binary := db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Find(db)
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test secondary password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
	if string(pw) != "AnotherPassword" {
		t.Fatalf(
			"Failed to decode password: should be 'AnotherPassword' not '%s'",
			pw,
		)
	}

	//
	// Test encode system on opened database
	//
	f, err := os.Create("tests/kdbx3/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	// Change the value of an entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = "http://github.com"

	// Lock entries
	err = db.LockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}

	// Test encoding
	enc := NewEncoder(f)
	err = enc.Encode(db)
	if err != nil {
		t.Fatalf("Failed to encode file: %s", err)
	}

	// Open the new database
	tmpfile, err := os.Open("tests/kdbx3/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer tmpfile.Close()

	// Decode the new database
	db = NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(tmpfile).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode temporary file: %s", err)
	}

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test new value matching
	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != "http://github.com" {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}
}

// Decode database v4.0
func TestDecodeFile4(t *testing.T) {
	// Open file
	file, err := os.Open("tests/kdbx4/example.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	// Decode database
	db := NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	// Test binary file matching
	binary := db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Find(db)
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test secondary password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
	if string(pw) != "AnotherPassword" {
		t.Fatalf(
			"Failed to decode password: should be 'AnotherPassword' not '%s'",
			pw,
		)
	}

	//
	// Test encode system on opened database
	//
	f, err := os.Create("tests/kdbx4/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	// Change the value of an entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = "http://github.com"

	// Lock entries
	err = db.LockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem locking entries. %s", err)
	}

	// Test encoding
	enc := NewEncoder(f)
	err = enc.Encode(db)
	if err != nil {
		t.Fatalf("Failed to encode file: %s", err)
	}

	// Open the new database
	tmpfile, err := os.Open("tests/kdbx4/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer tmpfile.Close()

	// Decode the new database
	db = NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(tmpfile).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode temporary file: %s", err)
	}

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test new value matching
	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != "http://github.com" {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}
}

// Decode database v3.1 with password and key
func TestDecodeFile31_Key(t *testing.T) {
	// Open file
	file, err := os.Open("tests/kdbx3/example-key.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	// Decode database
	db := NewDatabase()
	db.Credentials, err = NewPasswordAndKeyCredentials("abcdefg12345678", "tests/kdbx3/example-key.key")
	if err != nil {
		t.Fatalf("Failed to make credentials: %s", err)
	}
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	// Test binary file matching
	binary := db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Find(db)
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test secondary password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
	if string(pw) != "AnotherPassword" {
		t.Fatalf(
			"Failed to decode password: should be 'AnotherPassword' not '%s'",
			pw,
		)
	}
}

// Decode database v4.0 with password and key
func TestDecodeFile4_Key(t *testing.T) {
	// Open file
	file, err := os.Open("tests/kdbx4/example-key.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	// Decode database
	db := NewDatabase()
	db.Credentials, err = NewPasswordAndKeyCredentials("abcdefg12345678", "tests/kdbx4/example-key.key")
	if err != nil {
		t.Fatalf("Failed to make credentials: %s", err)
	}
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	// Test binary file matching
	binary := db.Content.Root.Groups[0].Groups[1].Entries[0].Binaries[0].Find(db)
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test password matching
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test secondary password matching
	pw = db.Content.Root.Groups[0].Groups[0].Entries[1].GetPassword()
	if string(pw) != "AnotherPassword" {
		t.Fatalf(
			"Failed to decode password: should be 'AnotherPassword' not '%s'",
			pw,
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

	newfile, err := os.Create("tests/new.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	newencoder := NewEncoder(newfile)
	err = newencoder.Encode(newdb)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Please open example/new.kdbx with keepass2 to verify that it works")

	// Test decode of the new file
	tmpfile, err := os.Open("tests/new.kdbx")
	if err != nil {
		t.Fatalf("Failed to open new keepass file: %s", err)
	}
	defer tmpfile.Close()

	// Decode the new database
	newdb = NewDatabase()
	newdb.Credentials = NewPasswordCredentials("password")
	err = NewDecoder(tmpfile).Decode(newdb)
	if err != nil {
		t.Fatalf("Failed to decode new keepass file: %s", err)
	}

	// Unlock entries
	err = newdb.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	// Test title matching
	if newdb.Content.Root.Groups[0].Entries[0].GetTitle() != "Sample Entry" {
		t.Fatalf("Decoding seemed to not work, title should be 'Sample Entry', was %s", newdb.Content.Root.Groups[0].Entries[0].GetTitle())
	}
}
