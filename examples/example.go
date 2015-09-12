package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib"
	"os"
)

func main() {
	file, _ := os.Open("./example.kdbx")

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("abcdefg12345678")
	_ = gokeepasslib.NewDecoder(file).Decode(db)

	db.UnlockProtectedEntries()

	entry := db.Content.Root.Groups[0].Groups[0].Entries[0]
	fmt.Println(entry.GetTitle())
	fmt.Println(entry.GetPassword())
}
