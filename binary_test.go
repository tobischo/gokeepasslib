package gokeepasslib

import (
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
	if data, _ := db.FindBinary(references[0].Value.ID).GetContentBytes(); string(data) != "test" {
		t.Fatalf("Binary Reference GetContentBytes is incorrect. Should be `test`, was '%s'", string(data))
	}
	if str, _ := db.FindBinary(references[0].Value.ID).GetContentString(); str != "test" {
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

func TestBinaryKDBXv4(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion4())

	randomData := make([]byte, 1024*1024)
	rand.Read(randomData)
	binary := db.AddBinary(randomData)

	found := db.FindBinary(binary.ID)
	if data, _ := found.GetContentBytes(); string(data) != string(randomData) {
		t.Log("Received:", len(data))
		t.Log("Expexted:", len(randomData))
		t.Fatalf("Binary content from Find is incorrect")
	}
}
