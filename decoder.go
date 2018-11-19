package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"reflect"
)

// Decoder stores a reader which is expected to be in kdbx format
type Decoder struct {
	r io.Reader
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

func (d *Decoder) Decode(db *Database) (err error) {
	db.Header = new(DBHeader)
	if err = db.Header.ReadFrom(d.r); err != nil {
		return err
	}

	// Read hashes and validate them (Kdbx v4)
	if db.Header.IsKdbx4() {
		db.Hashes = new(DBHashes)
		if err = db.Hashes.ReadFrom(d.r); err != nil {
			return err
		}

		if db.Options.ValidateHashes {
			if err := db.Header.ValidateSha256(db.Hashes.Sha256); err != nil {
				return err
			}
		}
	}

	db.Content = new(DBContent)
	if db.Header.IsKdbx4() {
		// Read content block by block
		// In Kdbx v4 you must parse blocks before decrypt
		if err = db.Content.ReadFrom4(d.r); err != nil {
			return err
		}
	} else {
		// Insert temporarely content into RawData (it will be read later, after decompression)
		// In Kdbx v3.1 you must decrypt before parse blocks
		data, err := ioutil.ReadAll(d.r)
		if err != nil {
			return err
		}
		db.Content.RawData = data
	}

	return d.decodeContent(db)
}

func (d *Decoder) decodeContent(db *Database) error {
	// Calculate transformed key to make decrypt
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		return err
	}

	// Decrypt content
	mode, err := db.Decrypter(transformedKey)
	if err != nil {
		return err
	}
	decrypted := make([]byte, len(db.Content.RawData))
	mode.CryptBlocks(decrypted, db.Content.RawData)

	// Check for StreamStartBytes (Kdbx v3.1)
	if !db.Header.IsKdbx4() {
		startBytes := db.Header.FileHeaders.StreamStartBytes
		if !reflect.DeepEqual(decrypted[0:len(startBytes)], startBytes) {
			return errors.New("Database integrity check failed")
		}

		decrypted = decrypted[len(startBytes):]
	}

	var reader io.Reader
	reader = bytes.NewReader(decrypted)

	// Read and put the new decrypted content into RawData
	// Kdbx v3.1 content must be read after decryption
	if !db.Header.IsKdbx4() {
		if err = db.Content.ReadFrom31(reader); err != nil {
			return err
		}
		reader = bytes.NewReader(db.Content.RawData)
	}

	// Decompress if the header compression flag is 1 (gzip)
	if db.Header.FileHeaders.CompressionFlags == GzipCompressionFlag {
		r, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer r.Close()
		reader = r
	}

	// Read InnerHeader (Kdbx v4)
	if db.Header.IsKdbx4() {
		a, _ := ioutil.ReadAll(reader)
		reader = bytes.NewReader(a)

		// Get InnerHeader
		db.Content.InnerHeader = new(InnerHeader)
		if err = db.Content.InnerHeader.ReadFrom(reader); err != nil {
			return err
		}
	}

	// Decode xml
	xmlDecoder := xml.NewDecoder(reader)
	err = xmlDecoder.Decode(db.Content)
	if err != nil {
		return err
	}
	return nil
}
