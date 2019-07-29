package wrappers

import (
	"encoding/xml"
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
	if b.Valid {
		val := "False"
		if b.Bool {
			val = "True"
		}

		e.EncodeElement(val, start)
	}

	return nil
}

// UnmarshalXML unmarshals the boolean from d
func (b *BoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	b.Valid = true

	var val string
	d.DecodeElement(&val, &start)

	b.Bool = false
	if strings.ToLower(val) == "true" {
		b.Bool = true
	}

	return nil
}

// MarshalXMLAttr returns the encoded XML attribute
func (b *BoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if b.Valid {
		val := "False"
		if b.Bool {
			val = "True"
		}

		return xml.Attr{Name: name, Value: val}, nil
	}

	return xml.Attr{}, nil
}

// UnmarshalXMLAttr decodes a single XML attribute
func (b *BoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	b.Valid = true

	b.Bool = false
	if strings.ToLower(attr.Value) == "true" {
		b.Bool = true
	}

	return nil
}
