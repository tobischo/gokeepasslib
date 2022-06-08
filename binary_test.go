package gokeepasslib

import (
	"bytes"
	"crypto/rand"
	"fmt"
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

	entry := NewEntry(WithEntryFormattedTime(!db.Header.IsKdbx4()))
	entry.Binaries = append(entry.Binaries, binary.CreateReference("test"))
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

	db.LockProtectedEntries()
	var buffer bytes.Buffer
	encoder := NewEncoder(&buffer)
	encoder.Encode(db)
	db = NewDatabase(WithDatabaseKDBXVersion4())
	decoder := NewDecoder(bytes.NewReader(buffer.Bytes()))
	decoder.Decode(db)
	db.UnlockProtectedEntries()

	found := db.FindBinary(binary.ID)
	if data, _ := found.GetContentBytes(); string(data) != string(randomData) {
		t.Log("Received:", len(data))
		t.Log("Expexted:", len(randomData))
		t.Fatalf("Binary content from Find is incorrect")
	}
}

func TestBinaryKDBXv31CleanBinaries(t *testing.T) {
	db := NewDatabase()

	expected := []*Binary{}
	expectedContent := []string{}
	count := 5

	for i := 0; i < count; i++ {
		str := "test " + fmt.Sprint(i)
		expectedContent = append(expectedContent, str)
		expected = append(expected, db.AddBinary([]byte(str)))
	}

	if len(db.Content.Meta.Binaries) != count {
		t.Fatalf("Expected %d binary elements, found %d", count, len(db.Content.Meta.Binaries))
	}

	entry := NewEntry(WithEntryFormattedTime(!db.Header.IsKdbx4()))
	for i := 0; i < count; i++ {
		entry.Binaries = append(entry.Binaries, expected[i].CreateReference("test"))
	}
	db.Content.Root.Groups[0].Entries = []Entry{}
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

	binaries := db.Content.Root.Groups[0].Entries[0].Binaries
	for i := 0; i < count; i++ {
		found := db.FindBinary(binaries[i].Value.ID)
		if data, _ := found.GetContentString(); string(data) != expectedContent[i] {
			t.Fatalf("Binary content from FindBinary is incorrect. Should be `%s`, was '%s'", expectedContent[i], string(data))
		}
	}

	toRemove := map[int]bool{0: true, 2: true, 4: true}
	newBinaries := []BinaryReference{}
	newExpected := []*Binary{}
	newExpectedContent := []string{}
	for i := range binaries {
		if _, remove := toRemove[i]; !remove {
			newBinaries = append(newBinaries, binaries[i])
			newExpected = append(newExpected, expected[i])
			newExpectedContent = append(newExpectedContent, expectedContent[i])
		}
	}
	db.Content.Root.Groups[0].Entries[0].Binaries = newBinaries
	expected = newExpected
	expectedContent = newExpectedContent

	db.LockProtectedEntries()
	var buffer bytes.Buffer
	encoder := NewEncoder(&buffer)
	encoder.Encode(db)
	db = NewDatabase()
	decoder := NewDecoder(bytes.NewReader(buffer.Bytes()))
	decoder.Decode(db)
	db.UnlockProtectedEntries()

	if len(db.Content.Meta.Binaries) != len(expected) {
		t.Fatalf("Expected %d binary elements, found %d", len(expected), len(db.Content.Meta.Binaries))
	}

	for i := 0; i < len(expected); i++ {
		found := db.FindBinary(i)
		if found == nil {
			t.Fatalf("Binary (ID=%d) not found", i)
		}
		if data, _ := found.GetContentBytes(); string(data) != expectedContent[i] {
			t.Fatalf("Binary content from FindBinary is incorrect. Should be `%s`, was '%s'", expectedContent[i], string(data))
		}

		ref := db.Content.Root.Groups[0].Entries[0].Binaries[i]
		if ref.Value.ID != i {
			t.Fatalf("Binary reference is incorrect. Should be `%d`, was '%d'", i, ref.Value.ID)
		}
	}
}

func TestBinaryKDBXv4CleanBinaries(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion4())

	expected := []*Binary{}
	count := 5

	for i := 0; i < count; i++ {
		expected = append(expected, db.AddBinary([]byte("test "+fmt.Sprint(i))))
	}

	if len(db.Content.InnerHeader.Binaries) != count {
		t.Fatalf("Expected %d binary elements, found %d", count, len(db.Content.InnerHeader.Binaries))
	}

	entry := NewEntry(WithEntryFormattedTime(!db.Header.IsKdbx4()))
	for i := 0; i < count; i++ {
		entry.Binaries = append(entry.Binaries, expected[i].CreateReference("test"))
	}
	db.Content.Root.Groups[0].Entries = []Entry{}
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

	binaries := db.Content.Root.Groups[0].Entries[0].Binaries
	for i := 0; i < count; i++ {
		found := db.FindBinary(binaries[i].Value.ID)
		if data, _ := found.GetContentBytes(); string(data) != string(expected[i].Content) {
			t.Fatalf("Binary content from FindBinary is incorrect. Should be `%s`, was '%s'", string(expected[i].Content), string(data))
		}
	}

	toRemove := map[int]bool{0: true, 2: true, 4: true}
	newBinaries := []BinaryReference{}
	newExpected := []*Binary{}
	for i := range binaries {
		if _, remove := toRemove[i]; !remove {
			newBinaries = append(newBinaries, binaries[i])
			newExpected = append(newExpected, expected[i])
		}
	}
	db.Content.Root.Groups[0].Entries[0].Binaries = newBinaries
	expected = newExpected

	db.LockProtectedEntries()
	var buffer bytes.Buffer
	encoder := NewEncoder(&buffer)
	encoder.Encode(db)
	db = NewDatabase(WithDatabaseKDBXVersion4())
	decoder := NewDecoder(bytes.NewReader(buffer.Bytes()))
	decoder.Decode(db)
	db.UnlockProtectedEntries()

	if len(db.Content.InnerHeader.Binaries) != len(expected) {
		t.Fatalf("Expected %d binary elements, found %d", len(expected), len(db.Content.InnerHeader.Binaries))
	}

	for i := 0; i < len(expected); i++ {
		found := db.FindBinary(i)
		if found == nil {
			t.Fatalf("Binary (ID=%d) not found", i)
		}
		if data, _ := found.GetContentBytes(); string(data) != string(expected[i].Content) {
			t.Fatalf("Binary content from FindBinary is incorrect. Should be `%s`, was '%s'", string(expected[i].Content), string(data))
		}

		ref := db.Content.Root.Groups[0].Entries[0].Binaries[i]
		if ref.Value.ID != i {
			t.Fatalf("Binary reference is incorrect. Should be `%d`, was '%d'", i, ref.Value.ID)
		}
	}
}
