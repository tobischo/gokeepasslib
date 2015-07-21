gokeepasslib
============

[![Travis Build state](https://api.travis-ci.org/tobischo/gokeepasslib.svg)](https://travis-ci.org/tobischo/gokeepasslib)

gokeepasslib is a library which allows reading Keepass 2 files (kdbx).

### Example

```go

file, _ := os.Open("examples/example.kdbx")

db := gokeepasslib.NewDatabase()
db.Credentials = gokeepasslib.NewPasswordCredentials("abcdefg12345678")
_ = gokeepasslib.NewDecoder(file).Decode(db)

db.UnlockProtectedEntries()

entry := db.Content.Root.Groups[0].Groups[0].Entries[0]
fmt.Println(entry.GetTitle())
fmt.Println(string(entry.Password))

```

### TODO

* Add godoc comments
* Improve code readability
* Write more tests

### License
[LICENSE](LICENSE.md)

### Copyright
Copyright &copy; 2015 Tobias Schoknecht. All rights reserved.
