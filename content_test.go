package gokeepasslib

import (
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
		t.Fatal("Expected invalid uuid error, got: %s", err)
	}
}
