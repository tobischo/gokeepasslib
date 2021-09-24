package gokeepasslib

import (
	"testing"
)

// Tests that binaries can set and get content correctly compressed or uncompressed
func TestBinary(t *testing.T) {
	db := NewDatabase()
	binaries := Binaries{}

	binary := binaries.Add([]byte("test"))
	binary.ID = 4

	binary2 := binaries.Add([]byte("replace me"))
	binary2.SetContent([]byte("Hello world!"))
	if binary2.ID != 5 {
		t.Fatalf("Binary2 assigned wrong id by binaries.Add, should be 5, was %d", binary2.ID)
	}

	if binaries.Find(2) != nil {
		t.Fatalf("Binaries.find for id 2 should be nil, wasn't")
	}

	// Put binaries var into Meta>Binaries, Kdbx v3.1 by default
	db.Content.Meta.Binaries = binaries

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

	found := binaries.Find(binary2.ID)
	if data, _ := found.GetContentBytes(); string(data) != "Hello world!" {
		t.Fatalf("Binary content from Find is inncorrect. Should be `Hello world!`, was '%s'", string(data))
	}
	if str, _ := found.GetContentString(); str != "Hello world!" {
		t.Fatalf("Binary content from Find is inncorrect. Should be `Hello world!`, was '%s'", str)
	}
}
