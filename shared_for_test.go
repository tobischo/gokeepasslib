package gokeepasslib

import (
	"os"
	"testing"
)

const (
	password        = "Password"
	anotherPassword = "AnotherPassword"

	// examplePassword is the credential of the example files in tests/
	examplePassword = "abcdefg12345678"

	// interopPassword is the credential of the fixtures which were generated
	// with another implementation
	interopPassword = "123"

	encodedIcon = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IA" +
		"rs4c6QAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAA" +
		"gOgAAHUwAADqYAAAOpgAABdwnLpRPAAAACZJREFUOE9jbGBo+M9ACQAZ" +
		"QAlmoEQz2PWjBoyGwWg6AGdCivMCAKxN4SAQ+6S+AAAAAElFTkSuQmCC"
	encodedIcon2 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IA" +
		"rs4c6QAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAA" +
		"gOgAAHUwAADqYAAAOpgAABdwnLpRPAAAACZJREFUOE9jbGBo+M9ACQAZ" +
		"QAlmoEQz2PWjBoyGwWg6AGdCivMCAKxN4SAQ+6S+AAAAAElFTkSuQmCC"
)

// decodeDatabase decodes the database at the given path and unlocks its
// protected values
func decodeDatabase(t *testing.T, path string, credentials string) *Database {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open keepass file: %s", err)
	}
	defer file.Close()

	db := NewDatabase()
	db.Credentials = NewPasswordCredentials(credentials)

	if err := NewDecoder(file).Decode(db); err != nil {
		t.Fatalf("Failed to decode file: %s", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock protected entries: %s", err)
	}

	return db
}
