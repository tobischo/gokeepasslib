package gokeepasslib

import "fmt"

// Signature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version

type Signature struct {
	BaseSignature    [4]byte
	VersionSignature [4]byte
	FileVersion      [4]byte
}

func (s Signature) String() string {
	return fmt.Sprintf("Base: %x, Version: %x, FileVersion: %x",
		s.BaseSignature,
		s.VersionSignature,
		s.FileVersion,
	)
}
