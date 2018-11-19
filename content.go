package gokeepasslib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

const (
	IH_TERMINATOR byte = 0x00
	IH_IRS_ID          = 0x01
	IH_IRS_KEY         = 0x02
	IH_BINARY          = 0x03
)

// Block size of 1MB - https://keepass.info/help/kb/kdbx_4.html#dataauth
const blockSplitRate = 1048576

type DBContent struct {
	RawData     []byte       `xml:"-"` // Encrypted data
	InnerHeader *InnerHeader `xml:"-"`
	XMLName     xml.Name     `xml:"KeePassFile"`
	Meta        *MetaData    `xml:"Meta"`
	Root        *RootData    `xml:"Root"`
}

type InnerHeader struct {
	InnerRandomStreamID  uint32
	InnerRandomStreamKey []byte
	Binaries             Binaries
}

func NewContent() *DBContent {
	// Not necessary create InnerHeader because this will be a KDBX v3.1
	return &DBContent{
		Meta: NewMetaData(),
		Root: NewRootData(),
	}
}

func (c *DBContent) ReadFrom4(r io.Reader) error {
	// Read the data block by block
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	c.RawData = []byte{}
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
			c.RawData = append(c.RawData, data...)
		} else {
			break
		}
	}
	return nil
}

func (c *DBContent) ReadFrom31(r io.Reader) error {
	// Read the data block by block
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	c.RawData = []byte{}
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

			// Add to blocks
			c.RawData = append(c.RawData, data...)
		} else {
			break
		}
	}
	return nil
}

func (ih *InnerHeader) ReadFrom(r io.Reader) error {
	binaryCount := 0 // Var used to count and index every binary
	for {
		var typ byte
		var length int32
		var data []byte

		if err := binary.Read(r, binary.LittleEndian, &typ); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return err
		}
		data = make([]byte, length)
		if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
			return err
		}

		if typ == IH_TERMINATOR {
			// End of inner header
			break
		} else if typ == IH_IRS_ID {
			// Found InnerRandomStream ID
			ih.InnerRandomStreamID = binary.LittleEndian.Uint32(data)
		} else if typ == IH_IRS_KEY {
			// Found InnerRandomStream Key
			ih.InnerRandomStreamKey = data
		} else if typ == IH_BINARY {
			// Found a binary
			var protection byte
			reader := bytes.NewReader(data)

			binary.Read(reader, binary.LittleEndian, &protection) // Read memory protection flag
			content, _ := ioutil.ReadAll(reader)                  // Read content

			ih.Binaries = append(ih.Binaries, Binary{
				ID:               binaryCount,
				MemoryProtection: protection,
				Content:          content,
			})

			binaryCount = binaryCount + 1
		} else {
			return ErrUnknownInnerHeaderID(typ)
		}
	}
	return nil
}

func (ih *DBContent) ComposeBlocks4(w io.Writer, contentData []byte, transformedKey []byte) {
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

func (ih *DBContent) ComposeBlocks31(w io.Writer, contentData []byte) {
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

func (ih *InnerHeader) WriteTo(w io.Writer) error {
	// InnerRandomStreamID
	if ih.InnerRandomStreamID != 0 {
		if err := binary.Write(w, binary.LittleEndian, uint8(IH_IRS_ID)); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(4)); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, ih.InnerRandomStreamID); err != nil {
			return err
		}
	}
	// InnerRandomStreamKey
	if len(ih.InnerRandomStreamKey) > 0 {
		if err := binary.Write(w, binary.LittleEndian, uint8(IH_IRS_KEY)); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(len(ih.InnerRandomStreamKey))); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, ih.InnerRandomStreamKey); err != nil {
			return err
		}
	}
	// Binaries
	for _, item := range ih.Binaries {
		if err := binary.Write(w, binary.LittleEndian, uint8(IH_BINARY)); err != nil {
			return err
		}
		// +1 byte for protection flag
		if err := binary.Write(w, binary.LittleEndian, uint32(len(item.Content)+1)); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, item.MemoryProtection); err != nil {

		}
		if err := binary.Write(w, binary.LittleEndian, item.Content); err != nil {
			return err
		}
	}
	// End inner header
	if err := binary.Write(w, binary.LittleEndian, uint8(IH_TERMINATOR)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(0)); err != nil {
		return err
	}
	return nil
}

func (ih InnerHeader) String() string {
	return fmt.Sprintf(
		"1) InnerRandomStreamID: %d\n"+
			"2) InnerRandomStreamKey: %x\n"+
			"3) Binaries: %s\n",
		ih.InnerRandomStreamID,
		ih.InnerRandomStreamKey,
		ih.Binaries,
	)
}

// Error for end of inner header
var ErrEndOfInnerHeaders = errors.New("gokeepasslib: inner header id was 0, end of inner headers")

// Error for unknown inner header id
type ErrUnknownInnerHeaderID byte

func (i ErrUnknownInnerHeaderID) Error() string {
	return fmt.Sprintf("gokeepasslib: unknown inner header ID of %x", i)
}
