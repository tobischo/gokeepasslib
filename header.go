package gokeepasslib

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// BaseSignature is the valid base signature for kdbx files
var BaseSignature = [...]byte{0x03, 0xd9, 0xa2, 0x9a}

// SecondarySignature is the valid version signature for kdbx files
var SecondarySignature = [...]byte{0x67, 0xfb, 0x4b, 0xb5}

// A full valid default signature struct for new databases (KDBX v3.1)
var DefaultSig = Signature{BaseSignature, SecondarySignature, 1, 3}

// CompressionFlags enum
const (
	NoCompressionFlag   uint32 = 0
	GzipCompressionFlag        = 1
)

// VariantDictionary type enum
const (
	VD_TERMINATOR byte = 0x00
	VD_UInt32          = 0x04
	VD_UInt64          = 0x05
	VD_Bool            = 0x08
	VD_Int32           = 0x0C
	VD_Int64           = 0x0D
	VD_String          = 0x18
	VD_ByteArray       = 0x42
)

// Ciphers
var CIPHER_AES = []byte{0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF}
var CIPHER_TWOFISH = []byte{0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C}
var CIPHER_CHACHA20 = []byte{0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A}

// Kdfs
var KDF_AES_3 = []byte{0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA}
var KDF_AES_4 = []byte{0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38}
var KDF_ARGON2 = []byte{0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C}

// Header of a database
// RawData is the byte array of the data
type DBHeader struct {
	RawData     []byte
	Signature   *Signature
	FileHeaders *FileHeaders
}

// FileSignature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version
type Signature struct {
	BaseSignature      [4]byte
	SecondarySignature [4]byte
	MinorVersion       uint16
	MajorVersion       uint16
}

// FileHeaders contains every field of the header
type FileHeaders struct {
	Comment             []byte             // FieldID: 1
	CipherID            []byte             // FieldID: 2
	CompressionFlags    uint32             // FieldID: 3
	MasterSeed          []byte             // FieldID: 4
	TransformSeed       []byte             // FieldID: 5 (KDBX 3.1)
	TransformRounds     uint64             // FieldID: 6 (KDBX 3.1)
	EncryptionIV        []byte             // FieldID: 7
	ProtectedStreamKey  []byte             // FieldID: 8 (KDBX 3.1)
	StreamStartBytes    []byte             // FieldID: 9 (KDBX 3.1)
	InnerRandomStreamID uint32             // FieldID: 10 (KDBX 3.1)
	KdfParameters       *KdfParameters     // FieldID: 11 (KDBX 4)
	PublicCustomData    *VariantDictionary // FieldID: 12 (KDBX 4)
}

// KdfParameters contains every field of the KdfParameters header field
type KdfParameters struct {
	RawData *VariantDictionary // Raw data of KdfParameters
	UUID    []byte             // $UUID for kdf
	R       uint64             // Rounds
	S       [32]byte           // Hash (Argon 2) / Seed (AES)
	P       uint32             // Parallelism
	M       uint64             // Memory
	I       uint64             // Iterations
	V       uint32             // Version
	K       []byte             // Secret key
	A       []byte             // AssocData
}

// VariantDictionary is a structure used into KdfParameters and PublicCustomData
type VariantDictionary struct {
	Version uint16
	Items   []*VariantDictionaryItem
}

// Item of a VariantDictionary
type VariantDictionaryItem struct {
	Type        byte
	NameLength  int32
	Name        []byte
	ValueLength int32
	Value       []byte
}

// Create a new Header with good defaults
func NewHeader() *DBHeader {
	return &DBHeader{
		Signature:   &DefaultSig,
		FileHeaders: NewFileHeaders(),
	}
}

// Create a new FileHeaders with good defaults
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
		CipherID:            []byte(CIPHER_AES),
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

// Read an header from a Reader
func (h *DBHeader) ReadFrom(r io.Reader) error {
	buffer := bytes.NewBuffer([]byte{})

	tR := io.TeeReader(r, buffer)

	// Read signature
	h.Signature = new(Signature)
	if err := binary.Read(tR, binary.LittleEndian, h.Signature); err != nil {
		return err
	}

	// Read file headers
	h.FileHeaders = new(FileHeaders)
	for {
		var err error
		if h.IsKdbx4() {
			err = h.FileHeaders.readHeader4(tR)
		} else {
			err = h.FileHeaders.readHeader31(tR)
		}

		// Update RawData buffer
		h.RawData = buffer.Bytes()

		if err != nil {
			if err == ErrEndOfHeaders {
				break
			}
			return err
		}
	}
	return nil
}

// Read header fields of KDBX v4
func (fh *FileHeaders) readHeader4(r io.Reader) error {
	var id uint8
	var length uint32
	var data []byte

	if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return err
	}
	data = make([]byte, length)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return err
	}

	if err := fh.readFileHeader(id, data); err != nil {
		return err
	}
	return nil
}

// Read header fields of KDBX v3.1
func (fh *FileHeaders) readHeader31(r io.Reader) error {
	var id uint8
	var length uint16
	var data []byte

	if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return err
	}
	data = make([]byte, length)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return err
	}

	if err := fh.readFileHeader(id, data); err != nil {
		return err
	}
	return nil
}

// Insert into FileHeaders every header found
func (fh *FileHeaders) readFileHeader(id uint8, data []byte) error {
	switch id {
	case 0:
		return ErrEndOfHeaders
	case 1:
		fh.Comment = data
	case 2:
		fh.CipherID = data
	case 3:
		fh.CompressionFlags = binary.LittleEndian.Uint32(data)
	case 4:
		fh.MasterSeed = data
	case 5:
		fh.TransformSeed = data
	case 6:
		fh.TransformRounds = binary.LittleEndian.Uint64(data)
	case 7:
		fh.EncryptionIV = data
	case 8:
		fh.ProtectedStreamKey = data
	case 9:
		fh.StreamStartBytes = data
	case 10:
		fh.InnerRandomStreamID = binary.LittleEndian.Uint32(data)
	case 11:
		dict := new(VariantDictionary)
		if err := dict.readVariantDictionary(data); err != nil {
			return err
		}

		fh.KdfParameters = new(KdfParameters)
		fh.KdfParameters.RawData = dict
		for _, item := range dict.Items {
			if err := fh.KdfParameters.readKdfParameter(item); err != nil {
				return err
			}
		}
	case 12:
		fh.PublicCustomData = new(VariantDictionary)
		return fh.PublicCustomData.readVariantDictionary(data)
	default:
		return ErrUnknownHeaderID(id)
	}
	return nil
}

// Insert into KdfParameters every parameter found
func (k *KdfParameters) readKdfParameter(vdi *VariantDictionaryItem) error {
	switch string(vdi.Name) {
	case "$UUID":
		k.UUID = vdi.Value
	case "R":
		k.R = binary.LittleEndian.Uint64(vdi.Value)
	case "S":
		copy(k.S[:], vdi.Value[:32])
	case "P":
		k.P = binary.LittleEndian.Uint32(vdi.Value)
	case "M":
		k.M = binary.LittleEndian.Uint64(vdi.Value)
	case "I":
		k.I = binary.LittleEndian.Uint64(vdi.Value)
	case "V":
		k.V = binary.LittleEndian.Uint32(vdi.Value)
	case "K":
		k.K = vdi.Value
	case "A":
		k.A = vdi.Value
	default:
		return ErrUnknownParameterID(string(vdi.Name))
	}
	return nil
}

// Read a VariantDictionary from a data
func (vd *VariantDictionary) readVariantDictionary(data []byte) error {
	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &vd.Version); err != nil {
		return err
	}

	for {
		vdi := new(VariantDictionaryItem)
		if err := binary.Read(r, binary.LittleEndian, &vdi.Type); err != nil {
			return err
		}

		if vdi.Type != VD_TERMINATOR {
			if err := binary.Read(r, binary.LittleEndian, &vdi.NameLength); err != nil {
				return err
			}
			vdi.Name = make([]byte, vdi.NameLength)
			if err := binary.Read(r, binary.LittleEndian, &vdi.Name); err != nil {
				return err
			}

			if err := binary.Read(r, binary.LittleEndian, &vdi.ValueLength); err != nil {
				return err
			}
			vdi.Value = make([]byte, vdi.ValueLength)
			if err := binary.Read(r, binary.LittleEndian, &vdi.Value); err != nil {
				return err
			}

			vd.Items = append(vd.Items, vdi)
		} else {
			break
		}
	}
	return nil
}

func (h *DBHeader) WriteTo(w io.Writer) error {
	var buffer bytes.Buffer
	mw := io.MultiWriter(w, &buffer)

	binary.Write(mw, binary.LittleEndian, h.Signature)

	if h.IsKdbx4() {
		h.FileHeaders.WriteTo4(mw, &buffer)
	} else {
		h.FileHeaders.WriteTo31(mw)
	}

	h.RawData = buffer.Bytes()

	return nil
}

func (fh FileHeaders) WriteTo4(w io.Writer, buf *bytes.Buffer) error {
	if err := writeTo4Header(w, 1, fh.Comment); err != nil {
		return err
	}
	if err := writeTo4Header(w, 2, fh.CipherID); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint8(3)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(4)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, fh.CompressionFlags); err != nil {
		return err
	}

	if err := writeTo4Header(w, 4, fh.MasterSeed); err != nil {
		return err
	}
	if err := writeTo4Header(w, 7, fh.EncryptionIV); err != nil {
		return err
	}
	if err := writeTo4VariantDictionary(w, 11, fh.KdfParameters.RawData); err != nil {
		return err
	}
	if err := writeTo4VariantDictionary(w, 12, fh.PublicCustomData); err != nil {
		return err
	}

	// End of header
	if err := binary.Write(w, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(4)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, []byte{0x0D, 0x0A, 0x0D, 0x0A}); err != nil {
		return err
	}
	return nil
}

func writeTo4Header(w io.Writer, id uint8, data []byte) error {
	if len(data) > 0 {
		if err := binary.Write(w, binary.LittleEndian, id); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return err
		}
	}
	return nil
}

func writeTo4VariantDictionary(w io.Writer, id uint8, data *VariantDictionary) error {
	if data != nil {
		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.LittleEndian, data.Version); err != nil {
			return err
		}
		for _, item := range data.Items {
			if err := binary.Write(&buffer, binary.LittleEndian, item.Type); err != nil {
				return err
			}
			if err := binary.Write(&buffer, binary.LittleEndian, item.NameLength); err != nil {
				return err
			}
			if err := binary.Write(&buffer, binary.LittleEndian, item.Name); err != nil {
				return err
			}
			if err := binary.Write(&buffer, binary.LittleEndian, item.ValueLength); err != nil {
				return err
			}
			if err := binary.Write(&buffer, binary.LittleEndian, item.Value); err != nil {
				return err
			}
		}
		if err := binary.Write(&buffer, binary.LittleEndian, VD_TERMINATOR); err != nil {
			return err
		}

		// Write to original writer
		if err := binary.Write(w, binary.LittleEndian, id); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint32(buffer.Len())); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, buffer.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func (fh FileHeaders) WriteTo31(w io.Writer) error {
	if err := writeTo31Header(w, 1, fh.Comment); err != nil {
		return err
	}
	if err := writeTo31Header(w, 2, fh.CipherID); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint8(3)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(4)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, fh.CompressionFlags); err != nil {
		return err
	}

	if err := writeTo31Header(w, 4, fh.MasterSeed); err != nil {
		return err
	}
	if err := writeTo31Header(w, 5, fh.TransformSeed); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint8(6)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(8)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, fh.TransformRounds); err != nil {
		return err
	}

	if err := writeTo31Header(w, 7, fh.EncryptionIV); err != nil {
		return err
	}
	if err := writeTo31Header(w, 8, fh.ProtectedStreamKey); err != nil {
		return err
	}
	if err := writeTo31Header(w, 9, fh.StreamStartBytes); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint8(10)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(4)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, fh.InnerRandomStreamID); err != nil {
		return err
	}

	// End of header
	if err := binary.Write(w, binary.LittleEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(4)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, []byte{0x0D, 0x0A, 0x0D, 0x0A}); err != nil {
		return err
	}
	return nil
}

func writeTo31Header(w io.Writer, id uint8, data []byte) error {
	if len(data) > 0 {
		if err := binary.Write(w, binary.LittleEndian, id); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, uint16(len(data))); err != nil {
			return err
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return err
		}
	}
	return nil
}

// Get a VariantDictionaryItem via the key
func (h *VariantDictionary) Get(key string) *VariantDictionaryItem {
	for _, item := range h.Items {
		if string(item.Name) == key {
			return item
		}
	}
	return nil
}

// Equals the header version to 4?
func (h *DBHeader) IsKdbx4() bool {
	return h.Signature.MajorVersion == 4
}

// Calculate SHA256 of header
func (h *DBHeader) GetSha256() [32]byte {
	return sha256.Sum256(h.RawData)
}

// Validate header SHA256 with the passed one
func (h *DBHeader) ValidateSha256(hash [32]byte) error {
	sha := sha256.Sum256(h.RawData)
	if !reflect.DeepEqual(sha, hash) {
		return errors.New("Sha256 of header mismatching")
	}
	return nil
}

func (h DBHeader) String() string {
	return fmt.Sprintf("Signature: %s\nFileHeaders: %s",
		h.Signature,
		h.FileHeaders,
	)
}
func (s Signature) String() string {
	return fmt.Sprintf("Base: %x, Secondary: %x, Format Version: %d.%d",
		s.BaseSignature,
		s.SecondarySignature,
		s.MajorVersion,
		s.MinorVersion,
	)
}
func (fh FileHeaders) String() string {
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
			"(10) InnerRandomStreamID: %x\n"+
			"(11) KdfParameters: \n%s\n"+
			"(12) PublicCustomData: \n%s\n",
		fh.Comment,
		fh.CipherID,
		fh.CompressionFlags,
		fh.MasterSeed,
		fh.TransformSeed,
		fh.TransformRounds,
		fh.EncryptionIV,
		fh.ProtectedStreamKey,
		fh.StreamStartBytes,
		fh.InnerRandomStreamID,
		fh.KdfParameters,
		fh.PublicCustomData,
	)
}
func (k *KdfParameters) String() string {
	return fmt.Sprintf(
		"  (1) R: %d\n"+
			"  (2) S: %x\n"+
			"  (3) P: %d\n"+
			"  (4) M: %d\n"+
			"  (5) I: %d\n"+
			"  (6) V: %d\n"+
			"  (7) K: %x\n"+
			"  (8) A: %x",
		k.R,
		k.S,
		k.P,
		k.M,
		k.I,
		k.V,
		k.K,
		k.A,
	)
}

func (vd VariantDictionary) String() string {
	var buffer bytes.Buffer
	for _, item := range vd.Items {
		buffer.WriteString(item.String())
	}
	return buffer.String()
}
func (vdi VariantDictionaryItem) String() string {
	return fmt.Sprintf("Type: %x, NameLength: %d, Name: %s, ValueLength: %d, Value: %x\n", vdi.Type, vdi.NameLength, string(vdi.Name), vdi.ValueLength, vdi.Value)
}

// ErrInvalidSignature is the error returned if the file signature is invalid
type ErrInvalidSignature struct {
	Name     string
	Is       interface{}
	Shouldbe interface{}
}

func (e ErrInvalidSignature) Error() string {
	return fmt.Sprintf("gokeepasslib: invalid signature. %s is %x. Should be %x", e.Name, e.Is, e.Shouldbe)
}

// Error for end of header
var ErrEndOfHeaders = errors.New("gokeepasslib: header id was 0, end of headers")

// Error for unknown header id
type ErrUnknownHeaderID int

func (i ErrUnknownHeaderID) Error() string {
	return fmt.Sprintf("gokeepasslib: unknown header ID of %d", i)
}

// Error for unknown kdf parameter
type ErrUnknownParameterID string

func (i ErrUnknownParameterID) Error() string {
	return fmt.Sprintf("gokeepasslib: unknown kdf parameter '%s'", i)
}
