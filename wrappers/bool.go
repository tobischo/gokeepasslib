package wrappers

import "encoding/xml"

// BoolWrapper is a bool wrapper that provides xml marshaling and unmarshaling
type BoolWrapper bool

// MarshalXML marshals the boolean into e
func (b *BoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := "False"
	if *b {
		val = "True"
	}
	e.EncodeElement(val, start)
	return nil
}

// UnmarshalXML unmarshals the boolean from d
func (b *BoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	*b = false
	if val == "True" {
		*b = true
	}

	return nil
}

// MarshalXMLAttr returns the encoded XML attribute
func (b *BoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := "False"
	if *b {
		val = "True"
	}

	return xml.Attr{Name: name, Value: val}, nil
}

// UnmarshalXMLAttr decodes a single XML attribute
func (b *BoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	*b = false
	if attr.Value == "True" {
		*b = true
	}

	return nil
}
