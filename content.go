package gokeepasslib

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

const (
	InnerHeaderTerminator byte = 0x00 // InnerHeader terminator byte
	InnerHeaderIRSID           = 0x01 // InnerHeader InnerRandomStreamID byte
	InnerHeaderIRSKey          = 0x02 // InnerHeader InnerRandomStreamKey byte
	InnerHeaderBinary          = 0x03 // InnerHeader binary byte
)

// DBContent is a container for all elements of a keepass database
type DBContent struct {
	RawData     []byte       `xml:"-"` // Encrypted data
	InnerHeader *InnerHeader `xml:"-"`
	XMLName     xml.Name     `xml:"KeePassFile"`
	Meta        *MetaData    `xml:"Meta"`
	Root        *RootData    `xml:"Root"`
}

// InnerHeader is the container of crypt options and binaries, only for Kdbx v4
type InnerHeader struct {
	InnerRandomStreamID  uint32
	InnerRandomStreamKey []byte
	Binaries             Binaries
}

// NewContent creates a new database content with some good defaults
func NewContent() *DBContent {
	// Not necessary create InnerHeader because this will be a KDBX v3.1
	return &DBContent{
		Meta: NewMetaData(),
		Root: NewRootData(),
	}
}

// readFrom reads the InnerHeader from an io.Reader
func (ih *InnerHeader) readFrom(r io.Reader) error {
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

		if typ == InnerHeaderTerminator {
			// End of inner header
			break
		} else if typ == InnerHeaderIRSID {
			// Found InnerRandomStream ID
			ih.InnerRandomStreamID = binary.LittleEndian.Uint32(data)
		} else if typ == InnerHeaderIRSKey {
			// Found InnerRandomStream Key
			ih.InnerRandomStreamKey = data
		} else if typ == InnerHeaderBinary {
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

// writeTo the InnerHeader to the given io.Writer
func (ih *InnerHeader) writeTo(w io.Writer) error {
	// InnerRandomStreamID
	if ih.InnerRandomStreamID != 0 {
		if err := binary.Write(w, binary.LittleEndian, uint8(InnerHeaderIRSID)); err != nil {
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
		if err := binary.Write(w, binary.LittleEndian, uint8(InnerHeaderIRSKey)); err != nil {
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
		if err := binary.Write(w, binary.LittleEndian, uint8(InnerHeaderBinary)); err != nil {
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
	if err := binary.Write(w, binary.LittleEndian, uint8(InnerHeaderTerminator)); err != nil {
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
