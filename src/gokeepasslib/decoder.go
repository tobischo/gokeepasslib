package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
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

	if sig.BaseSignature != [...]byte{0x03, 0xd9, 0xa2, 0x9a} {
		return errors.New("BaseSignature not valid")
	}
	if sig.VersionSignature != [...]byte{0x67, 0xfb, 0x4b, 0xb5} {
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

	_ = db.headers.StreamStartBytes
	//fmt.Printf("%b\n", startBytes)
	//fmt.Printf("%b\n", decrypted[0:len(startBytes)])
	// if decrypted[0:len(startBytes)] != startBytes[:] {
	// 	return errors.New("Database integrity check failed")
	// }

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

func (d *Decoder) buildMasterKey(db *Database) ([]byte, error) {
	masterKey := make([]byte, 32)
	copy(masterKey, db.credentials.Key)

	tmp := sha256.Sum256(masterKey)
	masterKey = tmp[:]

	block, err := aes.NewCipher(db.headers.TransformSeed)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Before: % x\n", masterKey)

	//http://crypto.stackexchange.com/questions/21048/can-i-simulate-iterated-aes-ecb-with-other-block-cipher-modes

	for i := uint32(0); i < 1; i++ {
		result := make([]byte, 16)
		crypter := cipher.NewCBCDecrypter(block, result)
		fmt.Printf("% x\n", result)
		crypter.CryptBlocks(result, masterKey[:16])
		fmt.Printf("% x\n", result)
		// copy(masterKey[:16], result[:16])
		// result = make([]byte, 16)
		// crypter = cipher.NewCBCEncrypter(block, masterKey[16:])
		// crypter.CryptBlocks(result, result)
		// copy(masterKey[16:], result[16:])
		//ecbCrypt(result, masterKey, block)
	}

	fmt.Printf("After:  % x\n", masterKey)
	fmt.Printf("Should be: % x\n", []byte{0x20, 0x07, 0xbb, 0x4b, 0xdc, 0xa2, 0x86, 0xfb, 0x92, 0x50, 0xf3, 0x9f, 0x11, 0x1b, 0xbf, 0x77, 0x7e, 0x07, 0xd3, 0x80, 0x7c, 0x4a, 0x4e, 0x57, 0xbb, 0xc3, 0x89, 0x4f, 0x30, 0x4e, 0x4c, 0x1f})
	// 06 f4 38 80 ef 1c f2 fa c8 64 e4 4d 9c 42 eb 74 33 e9 22 07 c4 0a d3 29 0e 07 af c3 03 7a f9 5b

	masterKey = append(db.headers.MasterSeed, masterKey...)
	masterHash := sha256.Sum256(masterKey)
	masterKey = masterHash[:]

	return masterKey, nil
}

func ecbCrypt(dst, src []byte, block cipher.Block) {
	length := len(src) / block.BlockSize()
	for i := 0; i < length; i++ {
		block.Encrypt(dst, src)
		src = src[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
}
