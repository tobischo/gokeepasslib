package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"reflect"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestNewContent(t *testing.T) {
	cases := []struct {
		title             string
		options           []DBContentOption
		expectedDBContent *DBContent
	}{
		{
			title: "without options",
			expectedDBContent: &DBContent{
				Meta: NewMetaData(),
				Root: NewRootData(),
			},
		},
		{
			title: "with multiple options",
			options: []DBContentOption{
				WithDBContentFormattedTime(false),
				func(c *DBContent) {
					c.RawData = []byte("hello world")
				},
			},
			expectedDBContent: &DBContent{
				RawData: []byte("hello world"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			content := NewContent(c.options...)

			if !bytes.Equal(content.RawData, c.expectedDBContent.RawData) {
				t.Errorf(
					"Did not receive expected content %+v, received %+v",
					content.RawData,
					c.expectedDBContent.RawData,
				)
			}
		})
	}
}

func TestDBContentSetKdbxFormatVersion(t *testing.T) {
	cases := []struct {
		title                  string
		formattedInitValue     bool
		version                formatVersion
		expectedFormattedValue bool
	}{
		{
			title:                  "initialized as v3, changed to v4",
			formattedInitValue:     true,
			version:                4,
			expectedFormattedValue: false,
		},
		{
			title:                  "initialized as v4, changed to v3",
			formattedInitValue:     false,
			version:                3,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v3, not changed",
			formattedInitValue:     true,
			version:                3,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v4, not changed",
			formattedInitValue:     false,
			version:                4,
			expectedFormattedValue: false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			content := NewContent(
				WithDBContentFormattedTime(c.formattedInitValue),
			)

			content.setKdbxFormatVersion(c.version)

			// Takes a single time value as an example, as TimeData is independently tested.
			if content.Root.Groups[0].Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set group CreationTime formatted value accordingly")
			}

			if content.Meta.MasterKeyChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set meta MasterKeyChanged formatted value accordingly")
			}
		})
	}

}

func TestVUnmarshal(t *testing.T) {
	v := &V{}

	data := []byte(`<Value Protected="True">&lt;some content &amp; to be decoded &quot; &gt;
	</Value>`)

	expectedV := &V{
		Content: `<some content & to be decoded " >
	`,
		Protected: w.NewBoolWrapper(true),
	}

	err := xml.Unmarshal(data, v)
	if err != nil {
		t.Fatalf("Received an unexpected error unmarshaling V: %v", err)
	}

	if !reflect.DeepEqual(v, expectedV) {
		t.Fatalf(
			"Did not receive expected V %#v, received: %#v",
			expectedV,
			v,
		)
	}
}

func TestVMarshal(t *testing.T) {
	v := &V{
		Content: `<some content & to be encoded " >
	`,
		Protected: w.NewBoolWrapper(true),
	}

	expectedData := []byte(`<V Protected="True">` +
		`&lt;some content &amp; to be encoded &#34; &gt;&#xA;&#x9;` +
		`</V>`)

	data, err := xml.Marshal(v)
	if err != nil {
		t.Fatalf("Received an unexpected error marshaling V: %v", err)
	}

	if !reflect.DeepEqual(data, expectedData) {
		t.Fatalf(
			"Did not receive expected data %s, received: %s",
			expectedData,
			data,
		)
	}
}
