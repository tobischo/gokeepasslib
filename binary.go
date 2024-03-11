package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// Binaries Stores a slice of binaries in the metadata header of a database
// This will be used only on KDBX 3.1
// Since KDBX 4, binaries are stored into the InnerHeader
type Binaries []Binary

// Binary stores a binary found in the metadata header of a database
type Binary struct {
	ID               int           `xml:"ID,attr"`         // Index (Manually counted on KDBX v4)
	MemoryProtection byte          `xml:"-"`               // Memory protection flag (Only KDBX v4)
	Content          []byte        `xml:",innerxml"`       // Binary content
	Compressed       w.BoolWrapper `xml:"Compressed,attr"` // Compressed flag (Only KDBX v3.1)
	isKDBX4          bool          `xml:"-"`
}

// BinaryReference stores a reference to a binary which appears in the xml of an entry
type BinaryReference struct {
	Name  string `xml:"Key"`
	Value struct {
		ID int `xml:"Ref,attr"`
	} `xml:"Value"`
}

// Find returns a reference to a binary with the same ID as id, or nil if none if found
func (bs Binaries) Find(id int) *Binary {
	for i := range bs {
		if bs[i].ID == id {
			return &bs[i]
		}
	}
	return nil
}

// Deprecated: Find returns a reference to a binary in the database db
// with the same id as br, or nil if none is found
// Note: this function should not be used directly, use `Database.FindBinary(id int) *Binary`
// instead
func (br *BinaryReference) Find(db *Database) *Binary {
	return db.getBinaries().Find(br.Value.ID)
}

// BinaryOption is the option function type for use with Binary structs
type BinaryOption func(binary *Binary)

// WithKDBXv4Binary can be passed to the Binaries.Add function as an option to ensure
// that the Binary will follow the KDBXv4 format
func WithKDBXv4Binary(binary *Binary) {
	binary.Compressed = w.NewBoolWrapper(false)
	binary.isKDBX4 = true
}

// WithKDBXv31Binary can be passed to the Binaries.Add function as an option to ensure
// that the Binary will follow the KDBXv31 format
func WithKDBXv31Binary(binary *Binary) {
	binary.Compressed = w.NewBoolWrapper(true)
	binary.isKDBX4 = false
}

// Deprecated: Add appends binary data to the slice
// Note: this function should not be used directly,
// use `Database.AddBinary(c []byte) *Binary` instead
func (bs *Binaries) Add(c []byte, options ...BinaryOption) *Binary {
	for _, binary := range *bs {
		if bytes.Equal(binary.Content, c) {
			return &binary
		}
	}

	binary := Binary{
		Compressed: w.NewBoolWrapper(true),
	}

	for _, option := range options {
		option(&binary)
	}

	if len(*bs) == 0 {
		binary.ID = 0
	} else {
		binary.ID = (*bs)[len(*bs)-1].ID + 1
	}
	binary.SetContent(c)
	*bs = append(*bs, binary)
	return &(*bs)[len(*bs)-1]
}

// GetContentBytes returns a bytes slice containing content of a binary
func (b Binary) GetContentBytes() ([]byte, error) {
	// Check for base64 content (KDBX 3.1), if it fail try with KDBX 4
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b.Content)))
	_, err := base64.StdEncoding.Decode(decoded, b.Content)
	if err != nil {
		// KDBX 4 doesn't encode it
		decoded = b.Content[:]
	}

	if b.Compressed.Bool {
		reader, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		bts, err := io.ReadAll(reader)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}

		return bts, nil
	}
	return decoded, nil
}

// GetContentString returns the content of a binary as a string
func (b Binary) GetContentString() (string, error) {
	data, err := b.GetContentBytes()

	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetContent returns a string which is the plaintext content of a binary
//
// Deprecated: use GetContentString() instead
func (b Binary) GetContent() (string, error) {
	return b.GetContentString()
}

type writeCloser struct {
	io.Writer
}

func (wc writeCloser) Close() error {
	return nil
}

// SetContent encodes and (if Compressed=true) compresses c and sets b's content
func (b *Binary) SetContent(c []byte) error {
	buff := &bytes.Buffer{}

	var writer io.WriteCloser

	if b.isKDBX4 {
		writer = writeCloser{Writer: buff}
	} else {
		writer = base64.NewEncoder(base64.StdEncoding, buff)
	}

	if b.Compressed.Bool {
		writer = gzip.NewWriter(writer)
	}
	_, err := writer.Write(c)
	if err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	b.Content = buff.Bytes()

	return nil
}

// CreateReference creates a reference with the same id as b with filename f
func (b Binary) CreateReference(f string) BinaryReference {
	return NewBinaryReference(f, b.ID)
}

// NewBinaryReference creates a new BinaryReference with the given name and id
func NewBinaryReference(name string, id int) BinaryReference {
	ref := BinaryReference{}
	ref.Name = name
	ref.Value.ID = id
	return ref
}

func (b Binary) String() string {
	return fmt.Sprintf(
		"ID: %d, MemoryProtection: %x, Compressed:%#v, Content:%x",
		b.ID,
		b.MemoryProtection,
		b.Compressed,
		b.Content,
	)
}
func (br BinaryReference) String() string {
	return fmt.Sprintf("ID: %d, File Name: %s", br.Value.ID, br.Name)
}
