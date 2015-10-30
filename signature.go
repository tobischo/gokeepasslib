package gokeepasslib

import (
	"encoding/binary"
	"fmt"
	"io"
)

//BaseSignature is the valid base signature for kdbx files
var BaseSignature = [...]byte{0x03, 0xd9, 0xa2, 0x9a}

//SecondarySignature is the valid version signature for kdbx files
var SecondarySignature = [...]byte{0x67, 0xfb, 0x4b, 0xb5}

//MajorVersion
const MajorVersion = 3

//MinorVersion
const MinorVersion = 1

//A full valid default signature struct for new databases
var DefaultSig = FileSignature{BaseSignature, SecondarySignature, MinorVersion, MajorVersion}

//ErrInvalidSignature is the error returned if the file signature is invalid
type ErrInvalidSignature struct {
	Name     string
	Is       interface{}
	Shouldbe interface{}
}

func (e ErrInvalidSignature) Error() string {
	return fmt.Sprintf("gokeepasslib: invalid signature. %s is %x. Should be %x", e.Name, e.Is, e.Shouldbe)
}

// FileSignature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version
type FileSignature struct {
	BaseSignature      [4]byte
	SecondarySignature [4]byte
	MinorVersion       uint16
	MajorVersion       uint16
}

func (s FileSignature) String() string {
	return fmt.Sprintf("Base: %x, Secondary: %x, Format Version: %d.%d",
		s.BaseSignature,
		s.SecondarySignature,
		s.MajorVersion,
		s.MinorVersion,
	)
}

// Validate checks the file signature for validity
func (s FileSignature) Validate() error {
	if s.BaseSignature != BaseSignature {
		return ErrInvalidSignature{"Base Signature", s.BaseSignature, BaseSignature}
	}
	if s.SecondarySignature != SecondarySignature {
		return ErrInvalidSignature{"Secondary Signature", s.SecondarySignature, SecondarySignature}
	}
	if s.MinorVersion != MinorVersion {
		return ErrInvalidSignature{"Minor Version", s.MinorVersion, MinorVersion}
	}
	if s.MajorVersion != MajorVersion {
		return ErrInvalidSignature{"Major Version", s.MajorVersion, MajorVersion}
	}
	return nil
}

// ReadFrom reads and validates the FileSignature from an io.Reader
func (s *FileSignature) ReadFrom(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, s); err != nil {
		return err
	}
	return s.Validate()
}

// WriteTo writes the FileSignature to a given writer
func (s FileSignature) WriteTo(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, s)
}
