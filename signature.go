package gokeepasslib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

//BaseSignature is the valid base signature for kdbx files
var BaseSignature = [...]byte{0x03, 0xd9, 0xa2, 0x9a}

//VersionSignature is the valid version signature for kdbx files
var VersionSignature = [...]byte{0x67, 0xfb, 0x4b, 0xb5}

//FileVersion is the most recent valid file version signature for kdbx files
var FileVersion = [...]byte{0x01, 0x00, 0x03, 0x00}

//A full valid default signature struct for new databases
var DefaultSig = FileSignature{BaseSignature, VersionSignature, FileVersion}

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

func (s *FileSignature) WriteSignature(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, s); err != nil {
		return err
	}

	return nil
}
