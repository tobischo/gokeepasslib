package main

import (
	"log"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: w.NewBoolWrapper(true)},
	}
}

func main() {
	filename := "example-writing.kdbx"
	masterPassword := "supersecret"

	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// create root group
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "root group"

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, mkValue("Title", "My GMail password"))
	entry.Values = append(entry.Values, mkValue("UserName", "example@gmail.com"))
	entry.Values = append(entry.Values, mkProtectedValue("Password", "hunter2"))

	rootGroup.Entries = append(rootGroup.Entries, entry)

	// demonstrate creating sub group (we'll leave it empty because we're lazy)
	subGroup := gokeepasslib.NewGroup()
	subGroup.Name = "sub group"

	subEntry := gokeepasslib.NewEntry()
	subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
	subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
	subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

	subGroup.Entries = append(subGroup.Entries, subEntry)

	rootGroup.Groups = append(rootGroup.Groups, subGroup)

	// now create the database containing the root group
	db := &gokeepasslib.Database{
		Header:      gokeepasslib.NewHeader(),
		Credentials: gokeepasslib.NewPasswordCredentials(masterPassword),
		Content: &gokeepasslib.DBContent{
			Meta: gokeepasslib.NewMetaData(),
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{rootGroup},
			},
		},
	}

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file: %s", filename)
}
