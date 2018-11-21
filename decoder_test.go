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
	db.Credentials, err = NewPasswordAndKeyCredentials(
		"abcdefg12345678",
		"tests/kdbx3/example-key.key",
	)
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
	db.Credentials, err = NewPasswordAndKeyCredentials(
		"abcdefg12345678",
		"tests/kdbx4/example-key.key",
	)
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
}

// Decode database v4.0 without compression
func TestDecodeFile4_NoCompression(t *testing.T) {
	// Open file
	file, err := os.Open("tests/kdbx4/example-nocompression.kdbx")
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
}
