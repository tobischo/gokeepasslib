package gokeepasslib

import "encoding/xml"

//Wraps the builtin boolean to provide xml marshaling and demarshaling
type boolWrapper bool

func (b *boolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := "False"
	if *b {
		val = "True"
	}
	e.EncodeElement(val, start)
	return nil
}

func (b *boolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	*b = false
	if val == "True" {
		*b = true
	}

	return nil
}

func (b *boolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := "False"
	if *b {
		val = "True"
	}

	return xml.Attr{Name: name, Value: val}, nil
}

func (b *boolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	*b = false
	if attr.Value == "True" {
		*b = true
	}

	return nil
}
