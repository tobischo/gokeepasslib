package main

import (
	"fmt"
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	file, _ := os.Open("./kpxc_twofish_example.kdbx")

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("test")
	err := gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		log.Fatal(err)
	}

	db.UnlockProtectedEntries()

	for _, group := range db.Content.Root.Groups {
		fmt.Println(group.Name)
		for _, entry := range group.Entries {
			fmt.Println(entry.GetTitle(), entry.GetPassword())
		}
	}
}
