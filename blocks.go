package gokeepasslib

import (
	"errors"
	"fmt"
	"encoding/binary"
	"crypto/sha256"
	"bytes"
)

//Size in bytes of the data in each block
const blockSplitRate = 16384

type ErrCorruptBlock struct {
	block *Block
	Hash [32]byte
}
func (e ErrCorruptBlock) Error () string {
	return fmt.Sprintf("Hash mismatch at block %d. Should be %x, is %x",e.block.Index,e.Hash,e.block.Hash)
}

var ErrBlockTooSmall = errors.New("gokeepasslib: block is too small")
var ErrEmptyBlock = errors.New("gokeepasslib: block appears to be empty/clossing block")


const minsize int = 40

type Block struct {
	Index  uint32
	Hash   [32]byte
	Length uint32
	Body   []byte
}
func NewBlock (i uint32, body []byte) (b Block) {
	b.Index = i
	b.Body = body
	b.Hash = sha256.Sum256(b.Body)
	b.Length = uint32(len(b.Body))
	return
}
func (u Block) MarshalText () (text []byte,err error) {
	text = make([]byte,u.Size())
	binary.LittleEndian.PutUint32(text[:4],u.Index)
	copy(text[4:36],u.Hash[:])
	binary.LittleEndian.PutUint32(text[36:40],u.Length)
	copy(text[40:],u.Body)
	return
}
func (b *Block) UnmarshalText(text []byte) error {
	if len (text) < minsize {
		return ErrBlockTooSmall
	}
	b.Index = binary.LittleEndian.Uint32(text[:4])
	copy(b.Hash[:],text[4:36])
	b.Length = binary.LittleEndian.Uint32(text[36:40])
	if b.Length == 0 {
		return ErrEmptyBlock
	}
	if len(text)-40 < int(b.Length) {
		return ErrBlockTooSmall
	}
	b.Body = text[40:40+b.Length]
	calculatedHash := sha256.Sum256(b.Body)
	if !bytes.Equal(calculatedHash[:], b.Hash[:]) {
		return ErrCorruptBlock{b,calculatedHash}
	}
	return nil
}
func (b Block) Size () int {
	return 40+len(b.Body)
}
func (b Block) String () string {
	return fmt.Sprintf("Index: %d\nHash: %x\n,Length:%d\n\n",b.Index,b.Hash,b.Length)
}

func DecodeBlocks (body []byte) (result []byte,err error) {
	var block Block
	for len(body) > 0 {
		err = block.UnmarshalText(body)
		if err != nil {
			if err == ErrEmptyBlock {
				return result,nil
			}
			return result,err
		}
		result = append(result, block.Body...)
		body = body[block.Size():]
	}
	return
}

// Converts raw xml data to keepass's block format, which includes a hash of each block to check for data corruption,
// Every block contains the following elements:
// (4 bytes) ID : an unique interger id for this block
// (32 bytes) sha-256 hash of block data
// (4 bytes) size on bytes of the block data
// (Data Size Bytes) the actual xml data of the block, will be blockSplitRate bytes at most
func EncodeBlocks (data []byte) (result []byte,err error) {
	var i uint32
	for len(data) > 0 { //For each block
		var body []byte
		if len(data) >= blockSplitRate { //If there is enough data for another block, use blockSplitRate bytes of data for block
			body = append(body,data[:blockSplitRate]...)
		} else { //Otherwise just use what is remaining and clear data to break from the loop
			body = append(body,data...)
		}
		data = data[len(body):]
		block := NewBlock(i,body)
		content,_ := block.MarshalText()
		result = append(result,content...)
		i++
	}
	endblock,_ := Block{Index:i}.MarshalText()
	result = append(result,endblock...)
	return
}