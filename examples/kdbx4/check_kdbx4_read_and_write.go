package main

import (
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	// Read
	file, err := os.Open("./kdbx4.kdbx")
	if err != nil {
		log.Printf("Failed opening file: %+v", err)
		os.Exit(1)
	}
	defer file.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("123")
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		log.Printf("Decoding file: %+v", err)
		os.Exit(1)
	}

	// Write
	resultFile, err := os.Create("./kdbx4_result.kdbx")
	if err != nil {
		log.Printf("Failed opening file: %+v", err)
		os.Exit(1)
	}

	err = gokeepasslib.NewEncoder(resultFile).Encode(db)
	if err != nil {
		log.Printf("Encoding file: %+v", err)
		os.Exit(1)
	}
	resultFile.Close()

	// Read again
	file2, err := os.Open("./kdbx4_result.kdbx")
	if err != nil {
		log.Printf("Failed opening file: %+v", err)
		os.Exit(1)
	}
	defer file.Close()

	db2 := gokeepasslib.NewDatabase()
	db2.Credentials = gokeepasslib.NewPasswordCredentials("123")
	err = gokeepasslib.NewDecoder(file2).Decode(db2)
	if err != nil {
		log.Printf("Decoding file: %+v", err)
		os.Exit(1)
	}
}
