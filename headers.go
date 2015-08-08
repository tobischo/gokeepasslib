package gokeepasslib

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

//Constant enumerator for the inner random stream ID
const (
	NoStreamID    uint32 = 0
	ARC4StreamID         = 1
	SalsaStreamID        = 2
)

//Constants enumerator for compression flags
const (
	NoCompressionFlag   uint32 = 0
	GzipCompressionFlag        = 1
)

var AESCipherID = []byte{0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF}

var ErrEndOfHeaders = errors.New("gokeepasslib: header id was 0, end of headers")

type ErrUnknownHeaderID int

func (i ErrUnknownHeaderID) Error() string {
	return fmt.Sprintf("gokeepasslib: unknown header ID of %d", i)
}

// FileHeaders holds the header information of the Keepass File.
type FileHeaders struct {
	Comment             []byte // FieldID:  1
	CipherID            []byte // FieldID:  2
	CompressionFlags    uint32 // FieldID:  3
	MasterSeed          []byte // FieldID:  4
	TransformSeed       []byte // FieldID:  5
	TransformRounds     uint64 // FieldID:  6
	EncryptionIV        []byte // FieldID:  7
	ProtectedStreamKey  []byte // FieldID:  8
	StreamStartBytes    []byte // FieldID:  9
	InnerRandomStreamID uint32 // FieldID: 10
}

// NewFileHeaders creates a new FileHeaders with good defaults
func NewFileHeaders() *FileHeaders {
	masterSeed := make([]byte, 32)
	rand.Read(masterSeed)

	transformSeed := make([]byte, 32)
	rand.Read(transformSeed)

	encryptionIV := make([]byte, 16)
	rand.Read(encryptionIV)

	protectedStreamKey := make([]byte, 32)
	rand.Read(protectedStreamKey)

	streamStartBytes := make([]byte, 32)
	rand.Read(streamStartBytes)

	return &FileHeaders{
		CipherID:            []byte(AESCipherID),
		CompressionFlags:    GzipCompressionFlag,
		MasterSeed:          masterSeed,
		TransformSeed:       transformSeed,
		TransformRounds:     6000,
		EncryptionIV:        encryptionIV,
		ProtectedStreamKey:  protectedStreamKey,
		StreamStartBytes:    streamStartBytes,
		InnerRandomStreamID: SalsaStreamID,
	}
}

func (h FileHeaders) String() string {
	return fmt.Sprintf(
		"(1) Comment: %x\n"+
			"(2) CipherID: %x\n"+
			"(3) CompressionFlags: %d\n"+
			"(4) MasterSeed: %x\n"+
			"(5) TransformSeed: %x\n"+
			"(6) TransformRounds: %d\n"+
			"(7) EncryptionIV: %x\n"+
			"(8) ProtectedStreamKey: %x\n"+
			"(9) StreamStartBytes: %x\n"+
			"(10) InnerRandomStreamID: %d\n",
		h.Comment,
		h.CipherID,
		h.CompressionFlags,
		h.MasterSeed,
		h.TransformSeed,
		h.TransformRounds,
		h.EncryptionIV,
		h.ProtectedStreamKey,
		h.StreamStartBytes,
		h.InnerRandomStreamID,
	)
}

func (headers *FileHeaders) SetHeader(h Header) error {
	switch h.ID {
	case 0:
		return ErrEndOfHeaders
	case 1:
		headers.Comment = h.Data
	case 2:
		headers.CipherID = h.Data
	case 3:
		headers.CompressionFlags = binary.LittleEndian.Uint32(h.Data)
	case 4:
		headers.MasterSeed = h.Data
	case 5:
		headers.TransformSeed = h.Data
	case 6:
		headers.TransformRounds = binary.LittleEndian.Uint64(h.Data)
	case 7:
		headers.EncryptionIV = h.Data
	case 8:
		headers.ProtectedStreamKey = h.Data
	case 9:
		headers.StreamStartBytes = h.Data
	case 10:
		headers.InnerRandomStreamID = binary.LittleEndian.Uint32(h.Data)
	default:
		return ErrUnknownHeaderID(h.ID)
	}
	return nil
}

// ReadHeaders reads the headers from an io.Reader and
// creates a structure containing the parsed header information
func (h *FileHeaders) ReadFrom(r io.Reader) error {
	var header Header
	for {
		if err := header.ReadFrom(r); err != nil {
			return err
		}
		if err := h.SetHeader(header); err != nil {
			if err == ErrEndOfHeaders {
				return nil
			}
			return err
		}
	}
}

// WriteTo takes the contents of the corresponding FileHeaders struct
// and writes them to the given io.Writer
func (headers *FileHeaders) WriteTo(w io.Writer) error {
	var header Header
	var err error
	header = NewHeader(1, headers.Comment)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(2, headers.CipherID)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(3, make([]byte, 4))
	binary.LittleEndian.PutUint32(header.Data, headers.CompressionFlags)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(4, headers.MasterSeed)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(5, headers.TransformSeed)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(6, make([]byte, 8))
	binary.LittleEndian.PutUint64(header.Data, headers.TransformRounds)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(7, headers.EncryptionIV)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(8, headers.ProtectedStreamKey)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(9, headers.StreamStartBytes)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	header = NewHeader(10, make([]byte, 4))
	binary.LittleEndian.PutUint32(header.Data, headers.InnerRandomStreamID)
	if err = header.WriteTo(w); err != nil {
		return err
	}
	err = EndHeader.WriteTo(w)
	return err
}

var EndHeader = Header{0, 4, []byte{0x0d, 0x0a, 0x0d, 0x0a}}

type Header struct {
	ID     uint8
	Length uint16
	Data   []byte
}

// NewHeader creates a new header ,setting length automaticaly
func NewHeader(id int, data []byte) Header {
	return Header{
		ID:     uint8(id),
		Length: uint16(len(data)),
		Data:   data,
	}
}
func (h *Header) ReadFrom(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &h.ID); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Length); err != nil {
		return err
	}
	h.Data = make([]byte, h.Length)
	if err := binary.Read(r, binary.LittleEndian, h.Data); err != nil {
		return err
	}
	return nil
}
func (h Header) WriteTo(w io.Writer) error {
	if len(h.Data) > 0 {
		if err := binary.Write(w, binary.LittleEndian, h.ID); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, h.Length); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, h.Data); err != nil {
			return err
		}
	}
	return nil
}
func (h *Header) FixLength() {
	h.Length = uint16(len(h.Data))
}
func (h Header) String() string {
	return fmt.Sprintf("ID: %d, Length: %d, Data: %x", h.ID, h.Length, h.Data)
}
