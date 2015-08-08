package gokeepasslib

import (
	"encoding/binary"
	"fmt"
	"io"
)

//BaseSignature is the valid base signature for kdbx files
var BaseSignature = [...]byte{0x03, 0xd9, 0xa2, 0x9a}

//VersionSignature is the valid version signature for kdbx files
var VersionSignature = [...]byte{0x67, 0xfb, 0x4b, 0xb5}

//FileVersion is the most recent valid file version signature for kdbx files
var FileVersion = [...]byte{0x01, 0x00, 0x03, 0x00}

//MajorVersion
const MajorVersion = 3

//MinorVersion
const MinorVersion = 1

//A full valid default signature struct for new databases
var DefaultSig = FileSignature{BaseSignature, VersionSignature,MinorVersion,MajorVersion}

type ErrInvalidSignature struct {
	Name string
	Is interface{}
	Shouldbe interface{}
}
func (e ErrInvalidSignature) Error () string {
	return fmt.Sprintf("gokeepasslib: invalid signature. %s is %x. Should be %x",e.Name,e.Is,e.Shouldbe)
}

// FileSignature holds the Keepass File Signature.
// The first 4 Bytes are the Base Signature,
// followed by 4 Bytes for the Version of the Format
// which is followed by 4 Bytes for the File Version
type FileSignature struct {
	BaseSignature    [4]byte
	VersionSignature [4]byte
	MinorVersion     uint16
	MajorVersion     uint16
}

func (s FileSignature) String() string {
	return fmt.Sprintf("Base: %x, Version: %x, Format Version: %d.%d",
		s.BaseSignature,
		s.VersionSignature,
		s.MajorVersion,
		s.MinorVersion,
	)
}
func (s FileSignature) Validate() error {
	if s.BaseSignature != BaseSignature {
		return ErrInvalidSignature{"BaseSignature",s.BaseSignature,BaseSignature}
	}
	if s.VersionSignature != VersionSignature {
		return ErrInvalidSignature{"VersionSignature",s.VersionSignature,VersionSignature}
	}
	if s.MinorVersion != MinorVersion {
		return ErrInvalidSignature{"MinorVersion",s.MinorVersion,MinorVersion}
	}
	if s.MajorVersion != MajorVersion {
		return ErrInvalidSignature{"MajorVersion",s.MajorVersion,MajorVersion}
	}
	return nil
}
func (s *FileSignature) ReadFrom(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, s); err != nil {
		return err
	}
	return s.Validate()
}

func (s FileSignature) WriteTo(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, s)
}
