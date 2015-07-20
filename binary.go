package gokeepasslib

import (
	"fmt"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io/ioutil"
	"io"
)

//Stores a slice of binaries in the metadata header
type Binaries []Binary

//Stores a binary found in the metadata header
type Binary struct {
	Content    []byte     `xml:",innerxml"`
	ID         int         `xml:"ID,attr"`
	Compressed boolWrapper `xml:"Compressed,attr"`
}

func (b Binary) String () (string) {
	return fmt.Sprintf("ID: %d, Compressed:%t, Content:%x",b.ID,b.Compressed,b.Content)
}

//Stores a reference to binaries in entries
type BinaryReference struct {
	Name	 string	   `xml:"Key"`
	Value struct { 
		ID     int	`xml:"Ref,attr"`
	} `xml:"Value"`  
}

func (br BinaryReference) String () (string) {
	return fmt.Sprintf("ID: %d, File Name: %s",br.Value.ID,br.Name)
}

//Given a list of binaries bs, returns a reference to a binary with the same id as the reference, or nil
func (br *BinaryReference) Find (bs Binaries) (*Binary) {
	return bs.Find(br.Value.ID)
}

//Returns a reference to a binary with id in binaries, or nil if none found
func (bs Binaries) Find (id int) (*Binary) {
	for i,_ := range bs {
		if bs[i].ID == id {
			return &bs[i]
		}
	}
	return nil
}

//Returns a reader to read from the binary content, decompressing if nessesary
func (b Binary) GetContent () (string,error) {
	decoded := make([]byte,base64.StdEncoding.DecodedLen(len(b.Content)))
	_,err := base64.StdEncoding.Decode(decoded,b.Content)
	if err != nil {
		return "",err
	}
	if b.Compressed {
		reader,err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return "",err
		}
		defer reader.Close()
		bts, err := ioutil.ReadAll(reader)
		if err != nil && err != io.ErrUnexpectedEOF {
			return "",err
		}
		return string(bts), nil
	}
	return string(decoded),nil
}