package gokeepasslib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Block size of 1MB - https://keepass.info/help/kb/kdbx_4.html#dataauth
const blockSplitRate = 1048576

var (
	errHMACVerificationFailed = errors.New("failed to verify HMAC")
)

type BlockHMACBuilder struct {
	baseKey []byte
}

func NewBlockHMACBuilder(masterSeed []byte, transformedKey []byte) *BlockHMACBuilder {
	keyBuilder := sha512.New()
	keyBuilder.Write(masterSeed)
	keyBuilder.Write(transformedKey)
	keyBuilder.Write([]byte{0x01})
	baseKey := keyBuilder.Sum(nil)

	return &BlockHMACBuilder{
		baseKey: baseKey,
	}
}

func (b *BlockHMACBuilder) BuildHMAC(index uint64, length uint32, data []byte) []byte {
	blockKeyBuilder := sha512.New()
	binary.Write(blockKeyBuilder, binary.LittleEndian, index)
	blockKeyBuilder.Write(b.baseKey)
	blockKey := blockKeyBuilder.Sum(nil)

	mac := hmac.New(sha256.New, blockKey)
	binary.Write(mac, binary.LittleEndian, index)
	binary.Write(mac, binary.LittleEndian, length)
	mac.Write(data)
	return mac.Sum(nil)
}

// blockHeader4 is the header of a content block (Kdbx v4)
type blockHeader4 struct {
	HMAC   [32]byte
	Length uint32
}

// blockHeader31 is the header of a content block (Kdbx v3.1)
type blockHeader31 struct {
	Index  uint32
	Hash   [32]byte
	Length uint32
}

// decomposeContentBlocks4 decodes the content data block by block (Kdbx v4)
// Used to extract data blocks from the entire content
func decomposeContentBlocks4(
	r io.Reader,
	masterSeed []byte,
	transformedKey []byte,
) ([]byte, error) {
	var contentData bytes.Buffer

	hmacBuilder := NewBlockHMACBuilder(masterSeed, transformedKey)

	for index := uint64(0); ; index++ {
		var header blockHeader4
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			return nil, corruptedBlockError(index, err)
		}

		start := contentData.Len()
		if err := readBlockData(&contentData, r, header.Length); err != nil {
			return nil, corruptedBlockError(index, err)
		}
		data := contentData.Bytes()[start:]

		calculatedHMAC := hmacBuilder.BuildHMAC(index, header.Length, data)

		if subtle.ConstantTimeCompare(calculatedHMAC, header.HMAC[:]) == 0 {
			return nil, fmt.Errorf("%w for block %d", errHMACVerificationFailed, index)
		}

		if header.Length == 0 {
			break
		}
	}
	return contentData.Bytes(), nil
}

// decomposeContentBlocks31 decodes the content data block by block (Kdbx v3.1)
// Used to extract data blocks from the entire content
func decomposeContentBlocks31(r io.Reader) ([]byte, error) {
	var contentData bytes.Buffer

	for index := uint32(0); ; index++ {
		var header blockHeader31
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			return nil, corruptedBlockError(uint64(index), err)
		}

		if header.Index != index {
			return nil, fmt.Errorf(
				"%w: expected block %d, found block %d",
				ErrCorruptedDatabase,
				index,
				header.Index,
			)
		}

		// The final block is empty and has an empty hash
		if header.Length == 0 {
			if header.Hash != [32]byte{} {
				return nil, fmt.Errorf("%w: final block %d has a hash", ErrCorruptedDatabase, index)
			}
			break
		}

		start := contentData.Len()
		if err := readBlockData(&contentData, r, header.Length); err != nil {
			return nil, corruptedBlockError(uint64(index), err)
		}

		if sha256.Sum256(contentData.Bytes()[start:]) != header.Hash {
			return nil, fmt.Errorf("%w: hash of block %d mismatching", ErrCorruptedDatabase, index)
		}
	}
	return contentData.Bytes(), nil
}

// readBlockData appends the length bytes of block data from r to buf.
// buf only grows with the data actually read, so a damaged length cannot
// cause a huge allocation
func readBlockData(buf *bytes.Buffer, r io.Reader, length uint32) error {
	_, err := io.CopyN(buf, r, int64(length))
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// corruptedBlockError wraps an error which occurred while reading a content block
func corruptedBlockError(index uint64, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: block %d is incomplete: %w", ErrCorruptedDatabase, index, err)
	}
	return err
}

// composeContentBlocks4 composes every content block into a HMAC-LENGTH-DATA block scheme (Kdbx v4)
func composeContentBlocks4(
	w io.Writer,
	contentData []byte,
	masterSeed []byte,
	transformedKey []byte,
) {
	hmacBuilder := NewBlockHMACBuilder(masterSeed, transformedKey)

	var offset int
	var endOffset int
	var index = uint64(0)
	for {
		remainingLength := len(contentData[offset:])

		if remainingLength >= blockSplitRate {
			endOffset = offset + blockSplitRate
		} else {
			endOffset = offset + remainingLength
		}

		length := endOffset - offset
		data := make([]byte, length)
		copy(data, contentData[offset:endOffset])
		uLength := uint32(length)

		blockHMAC := hmacBuilder.BuildHMAC(index, uLength, data)

		w.Write(blockHMAC)
		binary.Write(w, binary.LittleEndian, uLength)
		w.Write(data)

		offset = endOffset

		if length == 0 {
			break
		}

		index++
	}
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}

// composeBlocks31 composes every content block
// into a INDEX-SHA-LENGTH-DATA block scheme (Kdbx v3.1)
func composeContentBlocks31(w io.Writer, contentData []byte) {
	index := uint32(0)
	offset := 0
	for offset < len(contentData) {
		var hash [32]byte
		var endOffset int

		if len(contentData[offset:]) >= blockSplitRate {
			endOffset = offset + blockSplitRate
		} else {
			endOffset = len(contentData)
		}

		data := contentData[offset:endOffset]
		length := uint32(len(data))
		hash = sha256.Sum256(data)

		binary.Write(w, binary.LittleEndian, index)
		binary.Write(w, binary.LittleEndian, hash)
		binary.Write(w, binary.LittleEndian, length)
		binary.Write(w, binary.LittleEndian, data)
		index++
		offset = endOffset
	}
	binary.Write(w, binary.LittleEndian, index)
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}
