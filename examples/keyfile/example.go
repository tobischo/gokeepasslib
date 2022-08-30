package main

import (
  "fmt"
  "log"
  "os"

  "github.com/tobischo/gokeepasslib/v3"
)

func main() {
  file, _ := os.Open("/Users/tobiasschoknecht/Downloads/Archive/test.kdbx")

  db := gokeepasslib.NewDatabase()
  credentials, err := gokeepasslib.NewPasswordAndKeyCredentials(
    "123",
    "/Users/tobiasschoknecht/Downloads/Archive/Untitled-3.key",
  )
  if err != nil {
    log.Fatal(err)
  }
  db.Credentials = credentials
  _ = gokeepasslib.NewDecoder(file).Decode(db)

  db.UnlockProtectedEntries()

  // Note: This is a simplified example and the groups and entries will depend on the specific file.
  // bound checking for the slices is recommended to avoid panics.
  for _, entry := range db.Content.Root.Groups[0].Entries {
    fmt.Println(entry.GetTitle())
    fmt.Println(entry.GetPassword())
  }

}
