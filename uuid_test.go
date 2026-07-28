package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"errors"
	"testing"
)

func TestZeroUUIDText(t *testing.T) {
	text, err := UUID{}.MarshalText()
	if err != nil {
		t.Fatalf("Error marshaling uuid: %s", err)
	}

	if string(text) != ZeroUUIDText {
		t.Errorf("Expected ZeroUUIDText to be '%s', received '%s'", text, ZeroUUIDText)
	}
}

func TestUUIDMarshalXML(t *testing.T) {
	uuid := UUID{}
	if err := uuid.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plA==")); err != nil {
		t.Fatalf("Error unmarshaling uuid: %s", err)
	}

	cases := []struct {
		title    string
		value    UUID
		element  string
		expected string
	}{
		{
			title:    "UUID",
			value:    uuid,
			element:  uuidElement,
			expected: "<UUID>rGnBe1gIikK89aZD6n/plA==</UUID>",
		},
		{
			title:    "zero UUID",
			value:    UUID{},
			element:  uuidElement,
			expected: "<UUID>" + ZeroUUIDText + "</UUID>",
		},
		{
			title:    "CustomIconUUID",
			value:    uuid,
			element:  customIconUUIDElement,
			expected: "<CustomIconUUID>rGnBe1gIikK89aZD6n/plA==</CustomIconUUID>",
		},
		{
			// KeePass only writes the element if a custom icon is set and the
			// KDBX XML schema expects it to reference an existing custom icon
			title:    "zero CustomIconUUID is omitted",
			value:    UUID{},
			element:  customIconUUIDElement,
			expected: "",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var buffer bytes.Buffer

			encoder := xml.NewEncoder(&buffer)
			start := xml.StartElement{Name: xml.Name{Local: c.element}}

			if err := encoder.EncodeElement(c.value, start); err != nil {
				t.Fatalf("Error marshaling uuid: %s", err)
			}

			if err := encoder.Flush(); err != nil {
				t.Fatalf("Error flushing encoder: %s", err)
			}

			if buffer.String() != c.expected {
				t.Errorf("Expected '%s', received '%s'", c.expected, buffer.String())
			}
		})
	}
}

func TestUUID(t *testing.T) {
	one := UUID{}
	err := one.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plA=="))
	if err != nil {
		t.Fatalf("Error unmarshaling uuid: %s", err.Error())
	}
	mar, err := one.MarshalText()
	if err != nil {
		t.Fatalf("Error marshaling uuid")
	}
	if string(mar) != "rGnBe1gIikK89aZD6n/plA==" {
		t.Fatalf("UUID marshaled incorrectly. Expececting %s, got %s", "rGnBe1gIikK89aZD6n/plA==", mar)
	}

	two := one
	if !two.Compare(one) {
		t.Fatalf("One and Two UUIDs should be equal, are not")
	}

	three := UUID{}
	err = three.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plABBBB=="))
	if !errors.Is(err, ErrInvalidUUIDLength) {
		t.Fatalf("Expected invalid uuid error, got: %s", err)
	}

	four := UUID{}
	err = four.UnmarshalText([]byte(""))
	if err != nil {
		t.Fatalf("Expected no error but received: %s", err)
	}

	five := UUID{}

	if five.Compare(four) {
		t.Fatalf("four and five UUIDs should not be equal but are")
	}
}
