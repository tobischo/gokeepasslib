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

	db := NewDatabase()
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
	str,err := binary.GetContent()
	if err != nil {
		t.Fatal("Error getting content from binary: ",err,str)
	}
	if str != "Hello world" {
		t.Fatalf("Binary content was not as expected, expected: `Hello world`, received `%s`",str)
	}
	
	db.UnlockProtectedEntries()
	pw := db.Content.Root.Groups[0].Groups[0].Entries[0].GetPassword()
	if string(pw) != "Password" {
		t.Fatalf(
			"Failed to decode password: should be 'Password' not '%s'",
			pw,
		)
	}

	f, err := os.Create("examples/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open file for writing: %s", err)
	}

	//Changes the value of a entry element to see if the change stays after decoding
	db.Content.Root.Groups[0].Groups[0].Entries[0].Get("URL").Value.Content = "http://github.com"

	enc := NewEncoder(f)
	enc.Encode(db)

	file, err = os.Open("examples/tmp.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}

	db = NewDatabase()
	db.Credentials = NewPasswordCredentials("abcdefg12345678")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	db.UnlockProtectedEntries()
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
