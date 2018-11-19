package gokeepasslib

import (
	"encoding/binary"
	"fmt"
	"io"
)

type DBHashes struct {
	Sha256 [32]byte
	Hmac   [32]byte
}

func NewHashes(header *DBHeader) *DBHashes {
	return &DBHashes{
		Sha256: header.GetSha256(),
	}
}

func (s *DBHashes) ReadFrom(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, s); err != nil {
		return err
	}
	return nil
}

func (hh DBHashes) WriteTo(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, hh)
}

func (hh DBHashes) String() string {
	return fmt.Sprintf(
		"(1) Sha256: %x\n"+
			"(2) Hmac: %x\n",
		hh.Sha256,
		hh.Hmac,
	)
}
