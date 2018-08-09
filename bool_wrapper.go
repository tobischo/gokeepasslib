package gokeepasslib

import "encoding/xml"

//Wraps the builtin boolean to provide xml marshaling and demarshaling
type BoolWrapper bool

func (b *BoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := "False"
	if *b {
		val = "True"
	}
	e.EncodeElement(val, start)
	return nil
}

func (b *BoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	*b = false
	if val == "True" {
		*b = true
	}

	return nil
}

func (b *BoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := "False"
	if *b {
		val = "True"
	}

	return xml.Attr{Name: name, Value: val}, nil
}

func (b *BoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	*b = false
	if attr.Value == "True" {
		*b = true
	}

	return nil
}
