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

//Size in bytes of the data in each block
const blockSplitRate = 16384

//Header to be put before xml content in kdbx file
var xmlHeader = []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>`)

//Encoder is used to automaticaly encrypt and write a database to a file, network, etc
type Encoder struct {
	w io.Writer
}

//Writes db to e's internal writer
func (e *Encoder) Encode(db *Database) error {
	return e.writeData(db)
}

//Creates a new encoder with writer w, identical to gokeepasslib.Encoder{w}
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

//Internal function to write database to encoder's writer, called by Encode
func (e *Encoder) writeData(db *Database) error {
	db.LockProtectedEntries()

	//Creates XML data with from database content, and appends header to top
	xmlData, err := xml.MarshalIndent(db.Content, "", "\t")
	if err != nil {
		return err
	}
	xmlData = append(xmlHeader, xmlData...)

	var hashData []byte
	if db.Headers.CompressionFlags == 1 { //If database header says to compress with gzip, compress xml data and put into block form
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)
		defer w.Close()

		if _, err = w.Write(xmlData); err != nil {
			return err
		}

		if err = w.Flush(); err != nil {
			return err
		}

		hashData, err = hashBlocks(b.Bytes())
		if err != nil {
			return err
		}
	} else { //Otherwise put un-compressed xml content into block form
		hashData, err = hashBlocks(xmlData)
		if err != nil {
			return err
		}
	}

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

	//Uses database credentials info to build encryption key
	masterKey, err := db.Credentials.buildMasterKey(db)
	if err != nil {
		return err
	}

	//Creates an AES cipher block from the masterkey
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}

	//Encrypts block data using AES block with initialization vector from header
	mode := cipher.NewCBCEncrypter(block, db.Headers.EncryptionIV)
	encrypted := make([]byte, len(hashData))
	mode.CryptBlocks(encrypted, hashData)

	//Writes file signature (tells program it's a kdbx file of x version)
	err = db.Signature.WriteSignature(e.w)
	if err != nil {
		return err
	}

	//Writes headers of database
	err = db.Headers.WriteHeaders(e.w)
	if err != nil {
		return err
	}

	//Writes the encrypted database content
	_, err = e.w.Write(encrypted)
	if err != nil {
		return err
	}

	return nil
}

/* Converts raw xml data to keepass's block format, which includes a hash of each block to check for data corruption,
 * Every block contains the following elements:
 * (4 bytes) ID : an unique interger id for this block
 * (32 bytes) sha-256 hash of block data
 * (4 bytes) size on bytes of the block data
 * (Data Size Bytes) the actual xml data of the block, will be blockSplitRate bytes at most
 */
func hashBlocks(data []byte) ([]byte, error) {
	b := new(bytes.Buffer)

	i := 0
	for len(data) > 0 { //For each block
		var block []byte
		if len(data) >= blockSplitRate { //If there is enough data for another block, use blockSplitRate bytes of data for block
			block = append(block, data[:blockSplitRate]...)
			data = data[blockSplitRate:]
		} else { //Otherwise just use what is remaining and clear data to break from the loop
			block = append(block, data[:len(data)]...)
			data = make([]byte, 0)
		}

		//Writes the block id to output, discussed above
		if err := binary.Write(b, binary.LittleEndian, uint32(i)); err != nil {
			return nil, err
		}

		//Hashes block data and appends to output
		hash := sha256.Sum256(block)
		if _, err := b.Write(hash[:]); err != nil {
			return nil, err
		}

		//Writes length of block data to output
		if err := binary.Write(b, binary.LittleEndian, uint32(len(block))); err != nil {
			return nil, err
		}

		//Writes block data
		if _, err := b.Write(block); err != nil {
			return nil, err
		}

		i++
	}

	//Adds empty block to output, so keepass knows data stream is over
	if err := binary.Write(b, binary.LittleEndian, uint32(i)); err != nil {
		return nil, err
	}
	endBlock := make([]byte, 36)
	if _, err := b.Write(endBlock); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
