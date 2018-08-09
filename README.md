gokeepasslib
============

[![Travis Build state](https://api.travis-ci.org/tobischo/gokeepasslib.svg)](https://travis-ci.org/tobischo/gokeepasslib)

gokeepasslib is a library which allows reading Keepass 2 files (kdbx).

Note: only Keepass v2.30 or higher is properly supported since earlier versions do not allow empty XML tags but expected self-closing tags (which is valid XML but not really supported by Golang on XML marshaling)
Basically: this lib can probably read most Keepass2 files, but only Keepass v2.30 can be expected to read files created in this lib.

### Example: reading a file

```go
package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib"
	"os"
)

func main() {
	file, _ := os.Open("examples/example.kdbx")

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("abcdefg12345678")
	_ = gokeepasslib.NewDecoder(file).Decode(db)

	db.UnlockProtectedEntries()

	entry := db.Content.Root.Groups[0].Groups[0].Entries[0]
	fmt.Println(entry.GetTitle())
	fmt.Println(entry.GetPassword())
}
```

Note the `db.UnlockProtectedEntries()` call: you have to unlock protected entries before using the database
and call `db.LockProtectedEntries()` before saving it to ensure that the passwords are not stored in plaintext in the xml.
In kdbx files, which are encrypted using the file credentials, fields are protected with another stream cipher.

### Example: writing a file

See [examples/example-writing.go](examples/example-writing.go)

### TODO

* Add godoc comments
* Improve code readability
* Write more tests

### License
[LICENSE](LICENSE.md)

### Copyright
Copyright &copy; 2018 Tobias Schoknecht. All rights reserved.
