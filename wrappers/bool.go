package wrappers

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// BoolWrapper is a bool wrapper that provides xml marshaling and unmarshaling
type BoolWrapper struct {
	Bool  bool
	Valid bool
}

func NewBoolWrapper(value bool) BoolWrapper {
	return BoolWrapper{
		Bool:  value,
		Valid: true,
	}
}

// MarshalXML marshals the boolean into e
func (b *BoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := "null"

	if b.Valid {
		val = "False"
		if b.Bool {
			val = "True"
		}
	}

	e.EncodeElement(val, start)

	return nil
}

// UnmarshalXML unmarshals the boolean from d
func (b *BoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	switch strings.ToLower(val) {
	case "null":
		b.Valid = false
		b.Bool = false
	case "true":
		b.Valid = true
		b.Bool = true
	case "false":
		b.Valid = true
		b.Bool = false
	default:
		return fmt.Errorf("invalid BoolWrapper value '%s'", val)
	}

	return nil
}

// MarshalXMLAttr returns the encoded XML attribute
func (b *BoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := "null"

	if b.Valid {
		val = "False"
		if b.Bool {
			val = "True"
		}
	}

	return xml.Attr{Name: name, Value: val}, nil
}

// UnmarshalXMLAttr decodes a single XML attribute
func (b *BoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	switch strings.ToLower(attr.Value) {
	case "null":
		b.Valid = false
		b.Bool = false
	case "true":
		b.Valid = true
		b.Bool = true
	case "false":
		b.Valid = true
		b.Bool = false
	default:
		return fmt.Errorf("invalid BoolWrapper value '%s'", attr.Value)
	}

	return nil
}
