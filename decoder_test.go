package gokeepass_lib

import (
	"fmt"
	"os"
	"testing"
)

func TestDecodeFile(t *testing.T) {
	file, err := os.Open("Passwords.kdbx")
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}

	db := new(Database)
	db.credentials = NewPasswordCredentials("cookies")
	err = NewDecoder(file).Decode(db)
	if err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	fmt.Printf("DB: %s\n", db)
}
