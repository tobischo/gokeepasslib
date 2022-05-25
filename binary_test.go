package gokeepasslib

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Tests that binaries can set and get content correctly compressed or uncompressed
func TestBinaryKDBXv31(t *testing.T) {
	db := NewDatabase()

	binary := db.AddBinary([]byte("test"))
	binary.ID = 4

	binary2 := db.AddBinary([]byte("replace me"))
	binary2.SetContent([]byte("Hello world!"))
	if binary2.ID != 5 {
		t.Fatalf("Binary2 assigned wrong id by binaries.Add, should be 5, was %d", binary2.ID)
	}

	if db.FindBinary(2) != nil {
		t.Fatalf("Binaries.find for id 2 should be nil, wasn't")
	}

	references := []BinaryReference{}
	references = append(references, binary.CreateReference("example.txt"))
	if references[0].Value.ID != 4 {
		t.Fatalf("Binary Reference ID is incorrect. Should be 4, was %d", references[0].Value.ID)
	}
	if data, _ := references[0].Find(db).GetContentBytes(); string(data) != "test" {
		t.Fatalf("Binary Reference GetContentBytes is incorrect. Should be `test`, was '%s'", string(data))
	}
	if str, _ := references[0].Find(db).GetContentString(); str != "test" {
		t.Fatalf("Binary Reference GetContentString is incorrect. Should be `test`, was '%s'", str)
	}

	found := db.FindBinary(binary2.ID)
	if data, _ := found.GetContentBytes(); string(data) != "Hello world!" {
		t.Fatalf("Binary content from FindBinary is incorrect. Should be `Hello world!`, was '%s'", string(data))
	}
	if str, _ := found.GetContentString(); str != "Hello world!" {
		t.Fatalf("Binary content from FindBinary is incorrect. Should be `Hello world!`, was '%s'", str)
	}
}

func TestBinaryKDBXv31RemoveBinary(t *testing.T) {
	db := NewDatabase()

	db.AddBinary([]byte("test 1"))
	binary2 := db.AddBinary([]byte("test 2"))
	binary3 := db.AddBinary([]byte("test 3"))
	db.AddBinary([]byte("test 4"))
	db.AddBinary([]byte("test 5"))

	if len(db.Content.Meta.Binaries) != 5 {
		t.Fatalf("Expected 5 binary elements, found %d", len(db.Content.Meta.Binaries))
	}

	found := db.FindBinary(binary2.ID)
	if data, _ := found.GetContentBytes(); string(data) != "test 2" {
		t.Fatalf("Binary content from FindBinary is incorrect. Should be `test 2`, was '%s'", string(data))
	}

	removed := db.RemoveBinary(binary2.ID)
	str, _ := removed.GetContentString()
	expectedStr, _ := binary2.GetContentString()
	if str != expectedStr {
		t.Fatalf(
			"Binary content from RemoveBinary is incorrect. Should be `%s`, was '%s'",
			expectedStr,
			str,
		)
	}

	if db.FindBinary(binary2.ID) != nil {
		t.Fatalf("Binary content from FindBinary is incorrect. It should be removed, but it still exists")
	}

	if db.FindBinary(binary3.ID) == nil {
		t.Fatalf("Binary content from FindBinary is incorrect. It should exist")
	}

	if len(db.Content.Meta.Binaries) != 4 {
		t.Fatalf("Expected 4 binary elements, found %d", len(db.Content.Meta.Binaries))
	}
}

func TestBinaryKDBXv4(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion4())

	randomData := make([]byte, 1024*1024)
	rand.Read(randomData)
	binary := db.AddBinary(randomData)

	db.LockProtectedEntries()
	var buffer bytes.Buffer
	encoder := NewEncoder(&buffer)
	encoder.Encode(db)
	db = NewDatabase(WithDatabaseKDBXVersion4())
	decoder := NewDecoder(bytes.NewReader(buffer.Bytes()))
	decoder.Decode(db)
	db.UnlockProtectedEntries()

	found := db.Content.InnerHeader.Binaries.Find(binary.ID)
	if data, _ := found.GetContentBytes(); string(data) != string(randomData) {
		t.Log("Received:", len(data))
		t.Log("Expexted:", len(randomData))
		t.Fatalf("Binary content from Find is incorrect")
	}
}

func TestBinaryKDBXv4RemoveBinary(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion4())

	db.AddBinary([]byte("test 1"))
	binary2 := db.AddBinary([]byte("test 2"))
	binary3 := db.AddBinary([]byte("test 3"))
	db.AddBinary([]byte("test 4"))
	db.AddBinary([]byte("test 5"))

	if len(db.Content.InnerHeader.Binaries) != 5 {
		t.Fatalf("Expected 5 binary elements, found %d", len(db.Content.InnerHeader.Binaries))
	}

	found := db.FindBinary(binary2.ID)
	if data, _ := found.GetContentBytes(); string(data) != "test 2" {
		t.Fatalf("Binary content from FindBinary is incorrect. Should be `test 2`, was '%s'", string(data))
	}

	removed := db.RemoveBinary(binary2.ID)
	str, _ := removed.GetContentString()
	expectedStr, _ := binary2.GetContentString()
	if str != expectedStr {
		t.Fatalf(
			"Binary content from RemoveBinary is incorrect. Should be `%s`, was '%s'",
			expectedStr,
			str,
		)
	}

	if db.FindBinary(binary2.ID) != nil {
		t.Fatalf("Binary content from FindBinary is incorrect. It should be removed, but it still exists")
	}

	if db.FindBinary(binary3.ID) == nil {
		t.Fatalf("Binary content from FindBinary is incorrect. It should exist")
	}

	if len(db.Content.InnerHeader.Binaries) != 4 {
		t.Fatalf("Expected 4 binary elements, found %d", len(db.Content.InnerHeader.Binaries))
	}
}
