package gokeepass_lib

// Headers holds the header information of the Keepass File.
type Headers struct {
	Comment             uint32 // FieldID:  1
	CipherID            uint32 // FieldID:  2
	CompressionFlags    []byte // FieldID:  3
	MasterSeed          uint32 // FieldID:  4
	TransaformSeed      uint32 // FieldID:  5
	TransformRounds     []byte // FieldID:  6
	EncryptionIV        uint32 // FieldID:  7
	ProtectedStreamKey  uint32 // FieldID:  8
	StreamStartBytes    uint32 // FieldID:  9
	InnerRandomStreamID uint32 // FieldID: 10
}

// 0: EndOfHeader
