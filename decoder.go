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

func (d *Decoder) Decode(db *Database) (err error) {
	db.Signature = new(FileSignature)
	if err = db.Signature.ReadFrom(d.r); err != nil {
		return err
	}

	db.Headers = new(FileHeaders)
	if err = db.Headers.ReadFrom(d.r); err != nil {
		return err
	}

	if err := d.readData(db); err != nil {
		return err
	}

	return nil
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

func (d *Decoder) readData(db *Database) error {
	in, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}

	mode, err := db.Decrypter()
	if err != nil {
		return err
	}
	decrypted := make([]byte, len(in))
	mode.CryptBlocks(decrypted, in)

	startBytes := db.Headers.StreamStartBytes
	if !reflect.DeepEqual(decrypted[0:len(startBytes)], startBytes) {
		return errors.New("Database integrity check failed")
	}
	decrypted = decrypted[len(startBytes):]

	var xmlDecoder *xml.Decoder
	if db.Headers.CompressionFlags == GzipCompressionFlag { //Unzip if the header compression flag is 1 for gzip
		zippedBody, err := DecodeBlocks(decrypted)
		if err != nil {
			return err
		}

		b := bytes.NewBuffer(zippedBody)
		r, err := gzip.NewReader(b)
		if err != nil {
			return err
		}
		defer r.Close()
		xmlDecoder = xml.NewDecoder(r)
	} else { //Otherwise assume it not compressed
		xmlDecoder = xml.NewDecoder(bytes.NewReader(decrypted))
	}

	db.Content = &DBContent{}
	err = xmlDecoder.Decode(db.Content)
	return err
}
