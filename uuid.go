package gokeepasslib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"
)

const (
	// uuidElement is the name of the element holding the UUID of an object
	uuidElement = "UUID"

	// customIconUUIDElement is the name of the element referencing a custom icon
	// in the CustomIcons of the MetaData
	customIconUUIDElement = "CustomIconUUID"
)

// ZeroUUIDText is the base64 representation of a zero UUID.
// KeePass writes it for elements which have to contain a UUID but which do not
// reference anything, e.g. the LastSelectedGroup of a new database.
const ZeroUUIDText = "AAAAAAAAAAAAAAAAAAAAAA=="

// ErrInvalidUUIDLength is an error which is returned during unmarshaling
// if the UUID does not have 16 bytes length
var ErrInvalidUUIDLength = errors.New("gokeepasslib: length of decoded UUID was not 16")

// UUID stores a universal identifier for each group+entry
type UUID [16]byte

// NewUUID returns a new randomly generated UUID
func NewUUID() UUID {
	var id UUID
	rand.Read(id[:])
	return id
}

// Compare allowes to check whether two instance of UUID are equal in value.
// This is used for searching a uuid
// UUID is a fixed-size [16]byte array, so direct comparison with == is safe
// and compares all elements.
func (u UUID) Compare(c UUID) bool {
	return u == c
}

// IsZero returns true if the UUID only consists of zero bytes,
// which is how KeePass expresses the absence of a UUID value
func (u UUID) IsZero() bool {
	return u == UUID{}
}

// MarshalXML marshals the UUID as the base64 encoded content of the given element.
//
// A zero valued CustomIconUUID is not written at all: KeePass only writes the
// element if a custom icon is actually set and the KDBX XML schema expects every
// CustomIconUUID to reference an icon in the CustomIcons of the MetaData.
func (u UUID) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if start.Name.Local == customIconUUIDElement && u.IsZero() {
		return nil
	}

	text, err := u.MarshalText()
	if err != nil {
		return err
	}

	return e.EncodeElement(string(text), start)
}

// MarshalText is a marshaler method to encode uuid content as base 64 and return it
func (u UUID) MarshalText() ([]byte, error) {
	text := make([]byte, 24)
	base64.StdEncoding.Encode(text, u[:])
	return text, nil
}

// UnmarshalText unmarshals a byte slice into a UUID by decoding the given data from base64
func (u *UUID) UnmarshalText(text []byte) error {
	id := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	length, err := base64.StdEncoding.Decode(id, text)
	if err != nil {
		return err
	}
	if length == 0 {
		*u = NewUUID()
		return nil
	}
	if length != 16 {
		return ErrInvalidUUIDLength
	}
	copy((*u)[:], id[:16])
	return nil
}
