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

// Binary stores a binary found in the metadata header of a database
type Binary struct {
	Content    []byte      `xml:",innerxml"`
	ID         int         `xml:"ID,attr"`
	Compressed boolWrapper `xml:"Compressed,attr"`
}

func (b Binary) String() string {
	return fmt.Sprintf("ID: %d, Compressed:%t, Content:%x", b.ID, b.Compressed, b.Content)
}

// BinaryReference stores a reference to a binary which appears in the xml of an entry
type BinaryReference struct {
	Name  string `xml:"Key"`
	Value struct {
		ID int `xml:"Ref,attr"`
	} `xml:"Value"`
}

func (br BinaryReference) String() string {
	return fmt.Sprintf("ID: %d, File Name: %s", br.Value.ID, br.Name)
}

// Find returns a reference to  a binary in the slice of binaries bs with the same id as br, or nil if none is found
func (br *BinaryReference) Find(bs Binaries) *Binary {
	return bs.Find(br.Value.ID)
}

// Find returns a reference to a binary with the same ID as id, or nil if none if found
func (bs Binaries) Find(id int) *Binary {
	for i, _ := range bs {
		if bs[i].ID == id {
			return &bs[i]
		}
	}
	return nil
}

// GetContent returns a string which is the plaintext content of a binary, may return an error if something goes wrong in decoding from base64 or decompressing
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
