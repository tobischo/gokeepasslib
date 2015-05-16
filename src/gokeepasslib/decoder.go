package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
)

type Decoder struct {
	r io.Reader
}

func (d *Decoder) Decode(db *Database) error {
	if err := d.readSignature(db); err != nil {
		return err
	}

	if err := d.readHeaders(db); err != nil {
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

func (d *Decoder) readSignature(db *Database) error {
	sig := new(Signature)
	if err := binary.Read(d.r, binary.LittleEndian, sig); err != nil {
		return err
	}

	// if sig.BaseSignature != [...]byte{0x9a, 0xa2, 0xd9, 0x03} {
	// 	return errors.New("BaseSignature not valid")
	// }
	// if sig.VersionSignature != [...]byte{0xb5, 0x4b, 0xfb, 0x67} {
	// 	return errors.New("VersionSignature not valid")
	// }

	db.signature = *sig
	return nil
}

func (d *Decoder) readHeaders(db *Database) error {
	headers := new(Headers)

	for {
		var fieldID byte
		if err := binary.Read(d.r, binary.LittleEndian, &fieldID); err != nil {
			return err
		}

		var fieldLength [2]byte
		if err := binary.Read(d.r, binary.LittleEndian, &fieldLength); err != nil {
			return err
		}

		var fieldData = make([]byte, binary.LittleEndian.Uint16(fieldLength[:]))
		if err := binary.Read(d.r, binary.LittleEndian, &fieldData); err != nil {
			return err
		}

		switch fieldID {
		case 1:
			headers.Comment = fieldData
		case 2:
			headers.CipherID = fieldData
		case 3:
			headers.CompressionFlags = binary.LittleEndian.Uint32(fieldData)
		case 4:
			headers.MasterSeed = fieldData
		case 5:
			headers.TransformSeed = fieldData
		case 6:
			data := binary.LittleEndian.Uint32(fieldData[4:8])*
				(1<<16)*(1<<16) +
				binary.LittleEndian.Uint32(fieldData[0:4])
			headers.TransformRounds = data
		case 7:
			headers.EncryptionIV = fieldData
		case 8:
			headers.ProtectedStreamKey = fieldData
		case 9:
			headers.StreamStartBytes = fieldData
		case 10:
			headers.InnerRandomStreamID = fieldData
		}

		if fieldID == 0 {
			break
		}
	}

	db.headers = *headers
	return nil
}

func (d *Decoder) readData(db *Database) error {
	block, err := aes.NewCipher(db.credentials.Key)
	if err != nil {
		return err
	}

	in, err := ioutil.ReadAll(d.r)
	if err != nil {
		return err
	}

	mode := cipher.NewCBCDecrypter(block, db.headers.EncryptionIV)
	decrypted := make([]byte, len(in))
	mode.CryptBlocks(decrypted, in)

	b := bytes.NewBuffer(decrypted)
	r, err := gzip.NewReader(b)
	if err != nil {
		return err
	}
	defer r.Close()
	result := []byte{}
	r.Read(result)

	fmt.Println(result)

	return nil
}
