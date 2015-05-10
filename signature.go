package gokeepass_lib

// Signature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version
type Signature struct {
	BaseSignature    uint32
	VersionSignature uint32
	FileVersion      uint32
}
