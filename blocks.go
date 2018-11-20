package gokeepasslib

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"io/ioutil"
)

// Block size of 1MB - https://keepass.info/help/kb/kdbx_4.html#dataauth
const blockSplitRate = 1048576

// decomposeContentBlocks4 decodes the content data block by block (Kdbx v4)
// Used to extract data blocks from the entire content
func decomposeContentBlocks4(r io.Reader) ([]byte, error) {
	var contentData []byte
	// Get all the content
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	offset := uint32(0)
	for {
		var hash [32]byte
		var length uint32
		var data []byte

		copy(hash[:], content[offset:offset+32])
		offset = offset + 32

		length = binary.LittleEndian.Uint32(content[offset : offset+4])
		offset = offset + 4

		if length > 0 {
			data = make([]byte, length)
			copy(data, content[offset:offset+length])
			offset = offset + length

			// Add to blocks
			contentData = append(contentData, data...)
		} else {
			break
		}
	}
	return contentData, nil
}

// decomposeContentBlocks31 decodes the content data block by block (Kdbx v3.1)
// Used to extract data blocks from the entire content
func decomposeContentBlocks31(r io.Reader) ([]byte, error) {
	var contentData []byte
	// Get all the content
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	offset := uint32(0)
	for {
		var hash [32]byte
		var length uint32
		var data []byte

		// Skipping Index, uint32
		offset = offset + 4

		copy(hash[:], content[offset:offset+32])
		offset = offset + 32

		length = binary.LittleEndian.Uint32(content[offset : offset+4])
		offset = offset + 4

		if length > 0 {
			data = make([]byte, length)
			copy(data, content[offset:offset+length])
			offset = offset + length

			// Add to decoded blocks
			contentData = append(contentData, data...)
		} else {
			break
		}
	}
	return contentData, nil
}

// composeContentBlocks4 composes every content block into a HMAC-LENGTH-DATA block scheme (Kdbx v4)
func composeContentBlocks4(w io.Writer, contentData []byte, transformedKey []byte) {
	offset := 0
	for offset < len(contentData) {
		var hash []byte
		var length uint32
		var data []byte

		if len(contentData[offset:]) >= blockSplitRate {
			data = append(data, contentData[offset:]...)
		} else {
			data = append(data, contentData...)
		}
		length = uint32(len(data))
		mac := hmac.New(sha256.New, transformedKey)
		mac.Write(data)
		hash = mac.Sum(nil)

		binary.Write(w, binary.LittleEndian, hash)
		binary.Write(w, binary.LittleEndian, length)
		binary.Write(w, binary.LittleEndian, data)
		offset = offset + blockSplitRate
	}
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}

// composeBlocks31 composes every content block into a INDEX-SHA-LENGTH-DATA block scheme (Kdbx v3.1)
func composeContentBlocks31(w io.Writer, contentData []byte) {
	index := uint32(0)
	offset := 0
	for offset < len(contentData) {
		var hash [32]byte
		var length uint32
		var data []byte

		if len(contentData[offset:]) >= blockSplitRate {
			data = append(data, contentData[offset:]...)
		} else {
			data = append(data, contentData...)
		}

		length = uint32(len(data))
		hash = sha256.Sum256(data)

		binary.Write(w, binary.LittleEndian, index)
		binary.Write(w, binary.LittleEndian, hash)
		binary.Write(w, binary.LittleEndian, length)
		binary.Write(w, binary.LittleEndian, data)
		index++
		offset = offset + blockSplitRate
	}
	binary.Write(w, binary.LittleEndian, index)
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}
