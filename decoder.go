package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"io"
	"reflect"
)

var (
	errInvalidHMACKey          = errors.New("Wrong password? HMAC-SHA256 of header mismatching")
	errDatabaseIntegrityFailed = errors.New("Wrong password? Database integrity check failed")
)

// Decoder stores a reader which is expected to be in kdbx format
type Decoder struct {
	r io.Reader
}

// NewDecoder creates a new decoder with reader r, identical to gokeepasslib.Decoder{r}
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// Decode populates given database with the data of Decoder reader
func (d *Decoder) Decode(db *Database) error {
	// Read header
	db.Header = new(DBHeader)
	if err := db.Header.readFrom(d.r); err != nil {
		return err
	}

	// Calculate transformed key to decrypt and calculate HMAC
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		return err
	}

	// Read hashes and validate them (Kdbx v4)
	if db.Header.IsKdbx4() {
		db.Hashes = new(DBHashes)
		err := db.Hashes.readFrom(d.r)
		if err != nil {
			return err
		}

		if db.Options.ValidateHashes {
			err = db.Header.ValidateSha256(db.Hashes.Sha256)
			if err != nil {
				return err
			}

			hmacKey := buildHmacKey(db, transformedKey)
			err = db.Header.ValidateHmacSha256(hmacKey, db.Hashes.Hmac)
			if err != nil {
				return errInvalidHMACKey
			}
		}
	}

	// Decode raw content
	rawContent, _ := io.ReadAll(d.r)
	if err != nil {
		return err
	}

	if err := decodeRawContent(db, rawContent, transformedKey); err != nil {
		return err
	}

	contentReader := bytes.NewReader(db.Content.RawData)

	// Read InnerHeader (Kdbx v4)
	if db.Header.IsKdbx4() {
		db.Content.InnerHeader = new(InnerHeader)
		err = db.Content.InnerHeader.readFrom(contentReader)
		if err != nil {
			return err
		}
	}

	// Decode xml
	xmlDecoder := xml.NewDecoder(contentReader)
	return xmlDecoder.Decode(db.Content)
}

func decodeRawContent(db *Database, content []byte, transformedKey []byte) error {
	var err error
	// Initialize content
	db.Content = new(DBContent)

	if db.Header.IsKdbx4() {
		// Decompose content blocks
		// In Kdbx v4 you must parse blocks before decrypt
		reader := bytes.NewReader(content)
		content, err = decomposeContentBlocks4(reader, db.Header.FileHeaders.MasterSeed, transformedKey)
		if err != nil {
			return err
		}
	} else {
		// In Kdbx v3.1 you must decrypt before parse blocks
		reader := bytes.NewReader(content)
		content, err = io.ReadAll(reader)
		if err != nil {
			return err
		}
	}

	// Decrypt content
	encrypter, err := db.GetEncrypterManager(transformedKey)
	if err != nil {
		return err
	}
	decryptedContent := encrypter.Decrypt(content)

	// Check for StreamStartBytes (Kdbx v3.1)
	if !db.Header.IsKdbx4() {
		startBytes := db.Header.FileHeaders.StreamStartBytes
		if !reflect.DeepEqual(decryptedContent[0:len(startBytes)], startBytes) {
			return errDatabaseIntegrityFailed
		}

		decryptedContent = decryptedContent[len(startBytes):]
	}

	// Decompose content blocks and update reader
	// Kdbx v3.1 content must be read after decryption
	if !db.Header.IsKdbx4() {
		reader := bytes.NewReader(decryptedContent)
		decryptedContent, err = decomposeContentBlocks31(reader)
		if err != nil {
			return err
		}
	}

	// Decompress if the header compression flag is 1 (gzip)
	if db.Header.FileHeaders.CompressionFlags == GzipCompressionFlag {
		reader := bytes.NewReader(decryptedContent)
		r, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer r.Close()

		decryptedContent, _ = io.ReadAll(r)
	}

	db.Content.RawData = decryptedContent
	return nil
}
