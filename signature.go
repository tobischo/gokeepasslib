package gokeepasslib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FileSignature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version
type FileSignature struct {
	BaseSignature    [4]byte
	VersionSignature [4]byte
	FileVersion      [4]byte
}

func (s FileSignature) String() string {
	return fmt.Sprintf("Base: %x, Version: %x, FileVersion: %x",
		s.BaseSignature,
		s.VersionSignature,
		s.FileVersion,
	)
}

func ReadSignature(r io.Reader) (*FileSignature, error) {
	sig := new(FileSignature)
	if err := binary.Read(r, binary.LittleEndian, sig); err != nil {
		return nil, err
	}

	if sig.BaseSignature != BaseSignature {
		return nil, errors.New("BaseSignature not valid")
	}
	if sig.VersionSignature != VersionSignature {
		return nil, errors.New("VersionSignature not valid")
	}

	return sig, nil
}
