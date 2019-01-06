package main

import (
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v2"
)

func main() {
	readFilename := "example-writing.kdbx"
	writeFilename := "example-deleting.kdbx"
	masterPassword := "supersecret"

	readFile, err := os.Open(readFilename)
	if err != nil {
		panic(err)
	}
	defer readFile.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(masterPassword)
	err = gokeepasslib.NewDecoder(readFile).Decode(db)
	if err != nil {
		panic(err)
	}

	// Unlock protected entries to handle stream cipher
	db.UnlockProtectedEntries()

	rootGroup := db.Content.Root.Groups[0]

	// Remove `My GMail password` entry from example-writing example
	rootGroup.Entries = rootGroup.Entries[:0]

	db.Content.Root.Groups[0] = rootGroup

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	writeFile, err := os.Create(writeFilename)
	if err != nil {
		panic(err)
	}
	defer writeFile.Close()

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(writeFile)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file: %s", writeFilename)
}
