package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
)

// Binaries Stores a slice of binaries in the metadata header of a database
type Binaries []Binary

// Find returns a reference to a binary with the same ID as id, or nil if none if found
func (bs Binaries) Find(id int) *Binary {
	for i, _ := range bs {
		if bs[i].ID == id {
			return &bs[i]
		}
	}
	return nil
}

// Add appends binary data to the slice
func (b *Binaries) Add(c []byte) *Binary {
	binary := Binary{Compressed: BoolWrapper(true)}
	if len(*b) == 0 {
		binary.ID = 0
	} else {
		binary.ID = (*b)[len(*b)-1].ID + 1
	}
	binary.SetContent(c)
	*b = append(*b, binary)
	return &(*b)[len(*b)-1]
}

// Binary stores a binary found in the metadata header of a database
type Binary struct {
	Content    []byte      `xml:",innerxml"`
	ID         int         `xml:"ID,attr"`
	Compressed BoolWrapper `xml:"Compressed,attr"`
}

func (b Binary) String() string {
	return fmt.Sprintf("ID: %d, Compressed:%t, Content:%x", b.ID, b.Compressed, b.Content)
}

// GetContent returns a string which is the plaintext content of a binary
func (b Binary) GetContent() (string, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b.Content)))
	_, err := base64.StdEncoding.Decode(decoded, b.Content)
	if err != nil {
		return "", err
	}
	if b.Compressed {
		reader, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return "", err
		}
		defer reader.Close()
		bts, err := ioutil.ReadAll(reader)
		if err != nil && err != io.ErrUnexpectedEOF {
			return "", err
		}
		return string(bts), nil
	}
	return string(decoded), nil
}

// SetContent encodes and (if Compressed=true) compresses c and sets b's content
func (b *Binary) SetContent(c []byte) error {
	buff := &bytes.Buffer{}
	writer := base64.NewEncoder(base64.StdEncoding, buff)
	if b.Compressed {
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

// BinaryReference stores a reference to a binary which appears in the xml of an entry
type BinaryReference struct {
	Name  string `xml:"Key"`
	Value struct {
		ID int `xml:"Ref,attr"`
	} `xml:"Value"`
}

// NewBinaryReference creates a new BinaryReference with the given name and id
func NewBinaryReference(name string, id int) BinaryReference {
	ref := BinaryReference{}
	ref.Name = name
	ref.Value.ID = id
	return ref
}

func (br BinaryReference) String() string {
	return fmt.Sprintf("ID: %d, File Name: %s", br.Value.ID, br.Name)
}

// Find returns a reference to  a binary in the slice of binaries bs with the same id as br, or nil if none is found
func (br *BinaryReference) Find(bs Binaries) *Binary {
	return bs.Find(br.Value.ID)
}
