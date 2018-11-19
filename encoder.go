package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"io"
)

// Header to be put before xml content in kdbx file
var xmlHeader = []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n")

// Encoder is used to automaticaly encrypt and write a database to a file, network, etc
type Encoder struct {
	w io.Writer
}

// NewEncoder creates a new encoder with writer w, identical to gokeepasslib.Encoder{w}
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes db to e's internal writer
func (e *Encoder) Encode(db *Database) (err error) {
	// Writes header
	if err = db.Header.WriteTo(e.w); err != nil {
		return err
	}

	// Calculate and write header hashes
	hash := db.Header.GetSha256()
	if db.Header.IsKdbx4() {
		db.Hashes.Sha256 = hash
		if err = db.Hashes.WriteTo(e.w); err != nil {
			return err
		}
	} else {
		db.Content.Meta.HeaderHash = base64.StdEncoding.EncodeToString(hash[:])
	}

	// Creates XML data with from database content, and appends header to top
	data, err := xml.MarshalIndent(db.Content, "", "\t")
	if err != nil {
		return err
	}
	data = append(xmlHeader, data...)

	// Write InnerHeader (Kdbx v4)
	if db.Header.IsKdbx4() {
		var ih bytes.Buffer
		if err = db.Content.InnerHeader.WriteTo(&ih); err != nil {
			return err
		}

		data = append(ih.Bytes(), data...)
	}

	// Decompress if the header compression flag is 1 (gzip)
	if db.Header.FileHeaders.CompressionFlags == GzipCompressionFlag {
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)

		if _, err = w.Write(data); err != nil {
			return err
		}

		// Close() needs to be explicitly called to write Gzip stream footer,
		// Flush() is not enough. some gzip decoders treat missing footer as error
		// while some don't). internally Close() also does flush.
		if err = w.Close(); err != nil {
			return err
		}

		data = b.Bytes()
	}

	// Calculate transformed key to make HMAC and encrypt
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		return err
	}

	// Compose blocks (Kdbx v3.1)
	if !db.Header.IsKdbx4() {
		var blocks bytes.Buffer
		db.Content.ComposeBlocks31(&blocks, data)

		// Append blocks to StreamStartBytes
		data = append(db.Header.FileHeaders.StreamStartBytes, blocks.Bytes()...)
	}

	// Adds padding to data as required to encrypt properly
	if len(data)%16 != 0 {
		padding := make([]byte, 16-(len(data)%16))
		for i := 0; i < len(padding); i++ {
			padding[i] = byte(len(padding))
		}
		data = append(data, padding...)
	}

	// Encrypt content
	mode, err := db.Encrypter(transformedKey)
	if err != nil {
		return err
	}
	encrypted := make([]byte, len(data))
	mode.CryptBlocks(encrypted, data)

	// Compose blocks (Kdbx v4)
	if db.Header.IsKdbx4() {
		var blocks bytes.Buffer
		db.Content.ComposeBlocks4(&blocks, encrypted, transformedKey)

		encrypted = blocks.Bytes()
	}

	// Writes the encrypted database content
	if _, err = e.w.Write(encrypted); err != nil {
		return err
	}

	return nil
}
