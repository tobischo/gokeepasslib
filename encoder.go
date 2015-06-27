package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"io"
)

const blockSplitRate = 16384

type Encoder struct {
	w io.Writer
}

func (e *Encoder) Encode(db *Database) error {
	err := e.writeData(db)
	if err != nil {
		return err
	}

	return nil
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

func (e *Encoder) writeData(db *Database) error {
	xmlHeader := []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>`)

	xmlData, err := xml.Marshal(db.Content)
	if err != nil {
		return err
	}

	xmlData = append(xmlHeader, xmlData...)

	b := new(bytes.Buffer)
	w := gzip.NewWriter(b)
	defer w.Close()

	if _, err = w.Write(xmlData); err != nil {
		return err
	}

	if err = w.Flush(); err != nil {
		return err
	}

	hashData, err := hashBlocks(b.Bytes())
	if err != nil {
		return err
	}

	hashData = append(db.Headers.StreamStartBytes, hashData...)

	masterKey, err := db.Credentials.buildMasterKey(db)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}

	if len(hashData)%32 != 0 {
		padding := make([]byte, 32-(len(hashData)%32))
		hashData = append(hashData, padding...)
	}

	mode := cipher.NewCBCEncrypter(block, db.Headers.EncryptionIV)
	encrypted := make([]byte, len(hashData))
	mode.CryptBlocks(encrypted, hashData)

	db.Signature.WriteSignature(e.w)
	db.Headers.WriteHeaders(e.w)
	e.w.Write(encrypted)

	return nil
}

func hashBlocks(data []byte) ([]byte, error) {
	b := new(bytes.Buffer)

	i := 0
	for len(data) > 0 {
		block := make([]byte, 0)
		if len(data) >= blockSplitRate {
			block = append(block, data[:blockSplitRate]...)
			data = data[blockSplitRate:]
		} else {
			block = append(block, data[:len(data)]...)
			data = make([]byte, 0)
		}

		if err := binary.Write(b, binary.LittleEndian, uint32(i)); err != nil {
			return nil, err
		}

		hash := sha256.Sum256(block)

		if _, err := b.Write(hash[:]); err != nil {
			return nil, err
		}

		if err := binary.Write(b, binary.LittleEndian, uint32(len(block))); err != nil {
			return nil, err
		}

		if _, err := b.Write(block); err != nil {
			return nil, err
		}

		i++
	}

	if err := binary.Write(b, binary.LittleEndian, uint32(i)); err != nil {
		return nil, err
	}

	endBlock := make([]byte, 36)
	if _, err := b.Write(endBlock); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
