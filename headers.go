package gokeepasslib

import "fmt"

// Headers holds the header information of the Keepass File.
type Headers struct {
	Comment             []byte // FieldID:  1
	CipherID            []byte // FieldID:  2
	CompressionFlags    uint32 // FieldID:  3
	MasterSeed          []byte // FieldID:  4
	TransformSeed       []byte // FieldID:  5
	TransformRounds     uint32 // FieldID:  6
	EncryptionIV        []byte // FieldID:  7
	ProtectedStreamKey  []byte // FieldID:  8
	StreamStartBytes    []byte // FieldID:  9
	InnerRandomStreamID []byte // FieldID: 10
}

// 0: EndOfHeader

func (h Headers) String() string {
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
			"(10) InnerRandomStreamID: %x\n",
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
