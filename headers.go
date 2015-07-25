package gokeepasslib

import (
	"crypto/rand"
	"encoding/binary"
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
			"(3) CompressionFlags: %x\n"+
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

// ReadHeaders reads the headers from an io.Reader and
// creates a structure containing the parsed header information
func ReadHeaders(r io.Reader) (*FileHeaders, error) {
	headers := new(FileHeaders)
	for {
		var fieldID byte
		if err := binary.Read(r, binary.LittleEndian, &fieldID); err != nil {
			return nil, err
		}

		var fieldLength [2]byte
		if err := binary.Read(r, binary.LittleEndian, &fieldLength); err != nil {
			return nil, err
		}

		var fieldData = make([]byte, binary.LittleEndian.Uint16(fieldLength[:]))
		if err := binary.Read(r, binary.LittleEndian, &fieldData); err != nil {
			return nil, err
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
			headers.TransformRounds = binary.LittleEndian.Uint64(fieldData)
		case 7:
			headers.EncryptionIV = fieldData
		case 8:
			headers.ProtectedStreamKey = fieldData
		case 9:
			headers.StreamStartBytes = fieldData
		case 10:
			headers.InnerRandomStreamID = binary.LittleEndian.Uint32(fieldData)
		}

		if fieldID == 0 {
			break
		}
	}

	return headers, nil
}

// WriteHeaders takes the contents of the corresponding FileHeaders struct
// and writes them to the given io.Writer
func (h *FileHeaders) WriteHeaders(w io.Writer) error {
	for i := 1; i <= 10; i++ {
		var data []byte
		switch i {
		case 1:
			data = append(data, h.Comment...)
		case 2:
			data = append(data, h.CipherID...)
		case 3:
			d := make([]byte, 4)
			binary.LittleEndian.PutUint32(d, h.CompressionFlags)
			data = append(data, d...)
		case 4:
			data = append(data, h.MasterSeed...)
		case 5:
			data = append(data, h.TransformSeed...)
		case 6:
			d := make([]byte, 8)
			binary.LittleEndian.PutUint64(d, h.TransformRounds)
			data = append(data, d...)
		case 7:
			data = append(data, h.EncryptionIV...)
		case 8:
			data = append(data, h.ProtectedStreamKey...)
		case 9:
			data = append(data, h.StreamStartBytes...)
		case 10:
			d := make([]byte, 4)
			binary.LittleEndian.PutUint32(d, h.InnerRandomStreamID)
			data = append(data, d...)
		}

		if len(data) > 0 {
			err := binary.Write(w, binary.LittleEndian, uint8(i))
			if err != nil {
				return err
			}

			l := len(data)
			err = binary.Write(w, binary.LittleEndian, uint16(l))
			if err != nil {
				return err
			}

			err = binary.Write(w, binary.LittleEndian, data)
			if err != nil {
				return err
			}
		}
	}

	// End of header
	err := binary.Write(w, binary.LittleEndian, uint8(0))
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.LittleEndian, uint16(4))
	if err != nil {
		return err
	}

	if _, err := w.Write([]byte{0x0d, 0x0a, 0x0d, 0x0a}); err != nil {
		return err
	}

	return nil
}
