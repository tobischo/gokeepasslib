package gokeepasslib

import (
	"os"
	"reflect"
	"testing"
)

const urlValue = "http://github.com"

// Encode database v3.1
func TestEncodeFile31(t *testing.T) {
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	//
	// Test encode system on db
	//
	f, err := os.Create("tests/kdbx3/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	// Change the value of an entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = urlValue
	// apply a custom item
	db.Content.Root.Groups[0].Groups[0].Entries[0].CustomIconUUID = UUID{
		0xde, 0xad, 0xbe, 0xef,
		0xc0, 0xff, 0xee, 0xde,
		0xed, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd,
	}
	db.Content.Meta.CustomIcons = []CustomIcon{
		{
			UUID{
				0xde, 0xad, 0xbe, 0xef,
				0xc0, 0xff, 0xee, 0xde,
				0xed, 0x01, 0x23, 0x45,
				0x67, 0x89, 0xab, 0xcd,
			},
			encodedIcon,
		},
	}

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
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != password {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test new value matching
	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != urlValue {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}

	if !reflect.DeepEqual(
		db.Content.Root.Groups[0].Groups[0].Entries[0].CustomIconUUID,
		UUID{
			0xde, 0xad, 0xbe, 0xef,
			0xc0, 0xff, 0xee, 0xde,
			0xed, 0x01, 0x23, 0x45,
			0x67, 0x89, 0xab, 0xcd,
		},
	) {
		t.Fatal("Failed to properly encode Custom ICON URL")
	}
	if !reflect.DeepEqual(
		db.Content.Meta.CustomIcons[0],
		CustomIcon{
			UUID{
				0xde, 0xad, 0xbe, 0xef,
				0xc0, 0xff, 0xee, 0xde,
				0xed, 0x01, 0x23, 0x45,
				0x67, 0x89, 0xab, 0xcd,
			},
			encodedIcon,
		},
	) {
		t.Fatal("Failed to properly store a custom icon in the Meta block")
	}
}

// Encode database v4.0
func TestEncodeFile4(t *testing.T) {
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	//
	// Test encode system on db
	//
	f, err := os.Create("tests/kdbx4/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	// Change the value of an entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = urlValue
	db.Content.Root.Groups[0].Groups[0].Entries[0].CustomIconUUID = UUID{
		0xde, 0xad, 0xbe, 0xef,
		0xc0, 0xff, 0xee, 0xde,
		0xed, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd,
	}
	db.Content.Meta.CustomIcons = []CustomIcon{
		{
			UUID{
				0xde, 0xad, 0xbe, 0xef,
				0xc0, 0xff, 0xee, 0xde,
				0xed, 0x01, 0x23, 0x45,
				0x67, 0x89, 0xab, 0xcd,
			},
			encodedIcon,
		},
	}

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
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != password {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test new value matching
	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != urlValue {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}
	if !reflect.DeepEqual(
		db.Content.Root.Groups[0].Groups[0].Entries[0].CustomIconUUID,
		UUID{
			0xde, 0xad, 0xbe, 0xef,
			0xc0, 0xff, 0xee, 0xde,
			0xed, 0x01, 0x23, 0x45,
			0x67, 0x89, 0xab, 0xcd,
		},
	) {
		t.Fatal("Failed to properly encode Custom ICON URL")
	}
	if !reflect.DeepEqual(
		db.Content.Meta.CustomIcons[0],
		CustomIcon{
			UUID{
				0xde, 0xad, 0xbe, 0xef,
				0xc0, 0xff, 0xee, 0xde,
				0xed, 0x01, 0x23, 0x45,
				0x67, 0x89, 0xab, 0xcd,
			},
			encodedIcon,
		},
	) {
		t.Fatal("Failed to properly store a custom icon in the Meta block")
	}
}

// Encode database v4.0 without compression
func TestEncodeFile4_NoCompression(t *testing.T) {
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

	// Unlock entries
	err = db.UnlockProtectedEntries()
	if err != nil {
		t.Fatalf("Problem unlocking entries. %s", err)
	}

	//
	// Test encode system on opened database
	//
	f, err := os.Create("tests/kdbx4/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	// Change the value of an entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = urlValue

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
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if pw != password {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	// Test new value matching
	url := db.Content.Root.Groups[0].Groups[0].Entries[0].GetContent("URL")
	if url != urlValue {
		t.Fatalf(
			"Failed to decode url: should be 'http://github.com' not '%s'",
			url,
		)
	}
}

// Create a brand new kdbx file using only the library
func TestCreateNewFile(t *testing.T) {
	newdb := NewDatabase()

	if newdb.Content.Root.Groups[0].Entries[0].GetTitle() != "Sample Entry" {
		t.Fatalf(
			"NewRootData() seemed to not work, title should be 'Sample Entry', was %s",
			newdb.Content.Root.Groups[0].Entries[0].GetTitle(),
		)
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
		t.Fatalf(
			"Decoding seemed to not work, title should be 'Sample Entry', was %s",
			newdb.Content.Root.Groups[0].Entries[0].GetTitle(),
		)
	}
}
