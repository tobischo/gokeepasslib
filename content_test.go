package gokeepasslib

import (
	"encoding/xml"
	"reflect"
	"testing"
	"time"
)

func TestNewTimeData(t *testing.T) {
	timeData := NewTimeData()
	if time.Since(*timeData.CreationTime) > time.Millisecond {
		t.Error("CreationTime not properly initialized: should be time.Now()")
	}
	if time.Since(*timeData.LastModificationTime) > time.Millisecond {
		t.Error("LastModificationTime not properly initialized: should be time.Now()")
	}
	if time.Since(*timeData.LastAccessTime) > time.Millisecond {
		t.Error("LastAccessTime not properly initialized: should be time.Now()")
	}
	if timeData.ExpiryTime != nil {
		t.Error("ExpiryTime not properly initialized: should be nil")
	}
	if time.Since(*timeData.LocationChanged) > time.Millisecond {
		t.Error("LocationChanged not properly initialized: should be time.Now()")
	}
}

func TestUUID(t *testing.T) {
	one := UUID{}
	err := one.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plA=="))
	if err != nil {
		t.Fatalf("Error unmarshaling uuid", err)
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
	if err != ErrInvalidUUIDLength {
		t.Fatalf("Expected invalid uuid error, got: %s", err)
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
