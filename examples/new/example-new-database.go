package main

import (
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	filename := "example-new-database.kdbx"
	masterPassword := "supersecret"

	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// create the new database
	db := gokeepasslib.NewDatabase(
		gokeepasslib.WithDatabaseKDBXVersion4(),
	)
	db.Content.Meta.DatabaseName = "KDBX4"
	db.Credentials = gokeepasslib.NewPasswordCredentials(masterPassword)

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file: %s", filename)
}
