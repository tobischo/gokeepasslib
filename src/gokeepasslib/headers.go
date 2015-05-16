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
		"(1) Comment: %s\n"+
			"(2) CipherID: %s\n"+
			"(3) CompressionFlags: %t\n"+
			"(4) MasterSeed: %s\n"+
			"(5) TransformSeed: %s\n"+
			"(6) TransformRounds: %t\n"+
			"(7) EncryptionIV: %s\n"+
			"(8) ProtectedStreamKey: %s\n"+
			"(9) StreamStartBytes: %s\n"+
			"(10) InnerRandomStreamID: %s\n",
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
