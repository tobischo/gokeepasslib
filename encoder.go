package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
)

// Header to be put before xml content in kdbx file
var xmlHeader = []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n")

// Encoder is used to automaticaly encrypt and write a database to a file, network, etc
type Encoder struct {
	w io.Writer
}

// Encode writes db to e's internal writer
func (e *Encoder) Encode(db *Database) (err error) {
	//Writes file signature (tells program it's a kdbx file of x version)
	if err = db.Signature.WriteTo(e.w); err != nil {
		return err
	}

	//Writes headers of database
	if err = db.Headers.WriteTo(e.w); err != nil {
		return err
	}

	//Write database content, encrypted
	if err = e.writeData(db); err != nil {
		return err
	}

	return nil
}

// NewEncoder creates a new encoder with writer w, identical to gokeepasslib.Encoder{w}
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// writeData is an internal function to write database to encoder's writer, called by Encode
func (e *Encoder) writeData(db *Database) error {
	// Creates XML data with from database content, and appends header to top
	xmlData, err := xml.MarshalIndent(db.Content, "", "\t")
	if err != nil {
		return err
	}
	xmlData = append(xmlHeader, xmlData...)

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

	mode, err := db.Encrypter()
	if err != nil {
		return err
	}
	encrypted := make([]byte, len(hashData))
	mode.CryptBlocks(encrypted, hashData)

	//Writes the encrypted database content
	if _, err = e.w.Write(encrypted); err != nil {
		return err
	}

	return nil
}
