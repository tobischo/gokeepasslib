package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"regexp"
)

// Header to be put before xml content in kdbx file
var xmlHeader = []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n")

// Encoder is used to automaticaly encrypt and write a database to a file, network, etc
type Encoder struct {
	w io.Writer
}

// Encode writes db to e's internal writer
func (e *Encoder) Encode(db *Database) error {
	return e.writeData(db)
}

// NewEncoder creates a new encoder with writer w, identical to gokeepasslib.Encoder{w}
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// writeData is an internal function to write database to encoder's writer, called by Encode
func (e *Encoder) writeData(db *Database) error {
	db.LockProtectedEntries()

	// Creates XML data with from database content, and appends header to top
	xmlData, err := xml.MarshalIndent(db.Content, "", "\t")
	if err != nil {
		return err
	}
	xmlData = append(xmlHeader, xmlData...)
	xmlData, err = encodingPostProcessing(xmlData)
	if err != nil {
		return err
	}

	if db.Headers.CompressionFlags == GzipCompressionFlag { //If database header says to compress with gzip, compress xml data and put into block form
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)
		defer w.Close()

		if _, err = w.Write(xmlData); err != nil {
			return err
		}

		if err = w.Flush(); err != nil {
			return err
		}

		xmlData = b.Bytes()
		if err != nil {
			return err
		}
	}
	hashData, err := EncodeBlocks(xmlData)

	//Appends the StreamStartBytes from db header to the blocked data, used to verify that the key is correct when decrypting
	hashData = append(db.Headers.StreamStartBytes, hashData...)

	//Adds padding to data as required to encrypt properly
	if len(hashData)%16 != 0 {
		padding := make([]byte, 16-(len(hashData)%16))
		for i := 0; i < len(padding); i++ {
			padding[i] = byte(len(padding))
		}
		hashData = append(hashData, padding...)
	}

	mode,err := db.Encrypter()
	if err != nil {
		return err
	}
	encrypted := make([]byte, len(hashData))
	mode.CryptBlocks(encrypted, hashData)

	//Writes file signature (tells program it's a kdbx file of x version)
	err = db.Signature.WriteSignature(e.w)
	if err != nil {
		return err
	}

	//Writes headers of database
	err = db.Headers.WriteTo(e.w)
	if err != nil {
		return err
	}

	//Writes the encrypted database content
	_, err = e.w.Write(encrypted)
	if err != nil {
		return err
	}

	return nil
}

func encodingPostProcessing(data []byte) ([]byte, error) {
	// Keepass2 requires binary reference values to written as self closing tags
	binRefReplacement, err := regexp.Compile("<Value Ref=\"(\\d+)\"></Value>")
	if err != nil {
		return nil, err
	}
	return binRefReplacement.ReplaceAll(data, []byte("<Value Ref=\"$1\"/>")), nil
}
