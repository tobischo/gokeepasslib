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

	if sig.BaseSignature != BaseSignature {
		return errors.New("BaseSignature not valid")
	}
	if sig.VersionSignature != VersionSignature {
		return errors.New("VersionSignature not valid")
	}

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
	masterKey, nil := d.buildMasterKey(db)

	block, err := aes.NewCipher(masterKey)
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

	startBytes := db.headers.StreamStartBytes
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

	db.content = &Content{}
	xmlDecoder := xml.NewDecoder(r)
	xmlDecoder.Decode(db.content)

	return nil
}

func (d *Decoder) buildMasterKey(db *Database) ([]byte, error) {
	masterKey := make([]byte, 32)
	copy(masterKey, db.credentials.Key)

	tmp := sha256.Sum256(masterKey)
	masterKey = tmp[:]

	block, err := aes.NewCipher(db.headers.TransformSeed)
	if err != nil {
		return nil, err
	}

	// http://crypto.stackexchange.com/questions/21048/can-i-simulate-iterated-aes-ecb-with-other-block-cipher-modes
	for i := uint32(0); i < db.headers.TransformRounds; i++ {
		result := make([]byte, 16)
		crypter := cipher.NewCBCEncrypter(block, result)
		crypter.CryptBlocks(masterKey[:16], masterKey[:16])
		crypter = cipher.NewCBCEncrypter(block, result)
		crypter.CryptBlocks(masterKey[16:], masterKey[16:])
	}

	tmp = sha256.Sum256(masterKey)
	masterKey = tmp[:]

	masterKey = append(db.headers.MasterSeed, masterKey...)
	masterHash := sha256.Sum256(masterKey)
	masterKey = masterHash[:]

	return masterKey, nil
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
