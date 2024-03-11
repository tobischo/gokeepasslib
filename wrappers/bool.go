package wrappers

import (
	"encoding/xml"
	"strings"
)

const (
	falseStr = `False`
	trueStr  = `True`
	nullStr  = `null`
)

func parseBoolValue(val string) bool {
	switch strings.ToLower(val) {
	case "true", "yes", "1", "enabled", "checked":
		return true
	default:
		return false
	}
}

// BoolWrapper is a bool wrapper that provides xml marshaling and unmarshaling
type BoolWrapper struct {
	Bool bool
}

// NewBoolWrapper initializes a wrapper type around a bool value which holds the given value
func NewBoolWrapper(value bool) BoolWrapper {
	return BoolWrapper{
		Bool: value,
	}
}

// MarshalXML marshals the boolean into e
func (b *BoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := falseStr

	if b.Bool {
		val = trueStr
	}

	e.EncodeElement(val, start)

	return nil
}

// UnmarshalXML unmarshals the boolean from d
func (b *BoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	b.Bool = parseBoolValue(val)

	return nil
}

// MarshalXMLAttr returns the encoded XML attribute
func (b *BoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := falseStr

	if b.Bool {
		val = trueStr
	}

	return xml.Attr{Name: name, Value: val}, nil
}

// UnmarshalXMLAttr decodes a single XML attribute
func (b *BoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	b.Bool = parseBoolValue(attr.Value)

	return nil
}

// NullableBoolWrapper is a bool wrapper that provides xml un-/marshalling
// and additionally allows "null" as value.
type NullableBoolWrapper struct {
	Bool  bool
	Valid bool
}

// NewNullableBoolWrapper initializes a new NewNullableBoolWrapper with the given value
// and valid `true`.
func NewNullableBoolWrapper(value bool) NullableBoolWrapper {
	return NullableBoolWrapper{
		Bool:  value,
		Valid: true,
	}
}

// MarshalXML marshals the boolean into e
func (b *NullableBoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := nullStr

	if b.Valid {
		val = falseStr
		if b.Bool {
			val = trueStr
		}
	}

	e.EncodeElement(val, start)

	return nil
}

// UnmarshalXML unmarshals the boolean from d
func (b *NullableBoolWrapper) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var val string
	d.DecodeElement(&val, &start)

	switch strings.ToLower(val) {
	case nullStr:
		b.Valid = false
		b.Bool = false
	default:
		b.Valid = true
		b.Bool = parseBoolValue(val)
	}

	return nil
}

// MarshalXMLAttr returns the encoded XML attribute
func (b *NullableBoolWrapper) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	val := nullStr

	if b.Valid {
		val = falseStr
		if b.Bool {
			val = trueStr
		}
	}

	return xml.Attr{Name: name, Value: val}, nil
}

// UnmarshalXMLAttr decodes a single XML attribute
func (b *NullableBoolWrapper) UnmarshalXMLAttr(attr xml.Attr) error {
	switch strings.ToLower(attr.Value) {
	case nullStr:
		b.Valid = false
		b.Bool = false
	default:
		b.Valid = true
		b.Bool = parseBoolValue(attr.Value)
	}

	return nil
}
