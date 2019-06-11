package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"reflect"
	"testing"
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

func TestVUnmarshal(t *testing.T) {
	v := &V{}

	data := []byte(`<Value Protected="True">&lt;some content &amp; to be decoded &quot; &gt;
	</Value>`)

	expectedV := &V{
		Content: `<some content & to be decoded " >
	`,
		Protected: true,
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
		Protected: true,
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
