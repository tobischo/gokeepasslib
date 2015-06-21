package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
)

var BaseSignature = [...]byte{0x03, 0xd9, 0xa2, 0x9a}
var VersionSignature = [...]byte{0x67, 0xfb, 0x4b, 0xb5}

type Decoder struct {
	r io.Reader
}

func (d *Decoder) Decode(db *Database) error {
	s, err := ReadSignature(d.r)
	if err != nil {
		return err
	}
	db.Signature = s

	h, err := ReadHeaders(d.r)
	if err != nil {
		return err
	}
	db.Headers = h

	if err := d.readData(db); err != nil {
		return err
	}

	return nil
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

func (d *Decoder) readData(db *Database) error {
	masterKey, nil := db.Credentials.buildMasterKey(db)

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}

	in, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, db.Headers.EncryptionIV)
	decrypted := make([]byte, len(in))
	mode.CryptBlocks(decrypted, in)

	startBytes := db.Headers.StreamStartBytes
	if !reflect.DeepEqual(decrypted[0:len(startBytes)], startBytes) {
		return errors.New("Database integrity check failed")
	}
	decrypted = decrypted[len(startBytes):]

	zippedBody, err := d.checkHashBlocks(decrypted)
	if err != nil {
		return err
	}

	b := bytes.NewBuffer(zippedBody)
	r, err := gzip.NewReader(b)
	if err != nil {
		return err
	}
	defer r.Close()

	db.Content = &DBContent{}
	xmlDecoder := xml.NewDecoder(r)
	xmlDecoder.Decode(db.Content)

	return nil
}

func (d *Decoder) checkHashBlocks(hashedBody []byte) ([]byte, error) {
	result := make([]byte, 0)

	for len(hashedBody) > 0 {
		index := binary.LittleEndian.Uint32(hashedBody[:4])
		hashedBody = hashedBody[4:]
		blockHash := hashedBody[:32]
		hashedBody = hashedBody[32:]
		blockLength := binary.LittleEndian.Uint32(hashedBody[:4])
		hashedBody = hashedBody[4:]

		if blockLength > 0 {
			blockData := hashedBody[:blockLength]
			hashedBody = hashedBody[blockLength:]
			calculatedHash := sha256.Sum256(blockData)

			if !reflect.DeepEqual(calculatedHash[:], blockHash[:]) {
				return nil, fmt.Errorf("Hash mismatch. Database seems to be corrupt at index %d", index)
			} else {
				result = append(result, blockData...)
			}
		} else {
			break
		}
	}

	return result, nil
}
