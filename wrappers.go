package gokeepasslib

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"
)

// Wraps the builtin boolean to provide xml marshaling and demarshaling
type BoolWrapper bool

type TimeWrapper time.Time

const intLimit int64 = 5000000000

// Now returns a TimeWrapper instance with the current time in UTC
func Now() TimeWrapper {
	return TimeWrapper(time.Now().In(time.UTC))
}

func (b *BoolWrapper) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	val := "False"
	if *b {
		val = "True"
	}
	e.EncodeElement(val, start)
	return nil
}

func (tw TimeWrapper) MarshalText() ([]byte, error) {
	t := time.Time(tw).In(time.UTC)
	if y := t.Year(); y < 0 || y >= 10000 {
		return nil, errYearOutsideOfRange
	}

	b := make([]byte, 0, len(time.RFC3339))
	return t.AppendFormat(b, time.RFC3339), nil
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

func (tw *TimeWrapper) UnmarshalText(data []byte) error {
	// Check for RFC string (KDBX 3.1), if it fail try with KDBX 4
	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		// KDBX v4
		// In version 4 the time is a base64 timestamp of seconds passed since 1/1/0001
		var buf int64

		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		_, err = base64.StdEncoding.Decode(decoded, data)
		if err != nil {
			return err
		}

		t := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
		for {
			if buf < intLimit {
				t = t.Add(time.Duration(buf) * time.Second)
				break
			} else {
				t = t.Add(time.Duration(intLimit) * time.Second)
				buf -= intLimit
			}
		}
	}
	*tw = TimeWrapper(t)
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

var errYearOutsideOfRange = errors.New("TimeWrapper.MarshalText: year outside of range [0,9999]")
