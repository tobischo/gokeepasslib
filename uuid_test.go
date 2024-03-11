package gokeepasslib

import (
	"errors"
	"testing"
)

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
