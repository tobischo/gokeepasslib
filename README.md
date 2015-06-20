gokeepasslib
============

gokeepasslib is a library which allows reading Keepass 2 files (kdbx).
It is mostly a port from the node.js implementation [keepass.io](https://github.com/NeoXiD/keepass.io)

### Example

```go

file, _ := os.Open("example.kdbx")

db := gokeepasslib.NewDatabase()
db.credentials = gokeepasslib.NewPasswordCredentials("abcdefg12345678")
_ = gokeepasslib.NewDecoder(file).Decode(db)

db.UnlockProtectedEntries()

entry := db.content.Root.Groups[0].Groups[0].Entries[0]
fmt.Println(entry.GetTitle())
fmt.Println(string(entry.Password))

```

### TODO

* Implement file writing
* Add godoc comments
* Write more tests

### License
[LICENSE](LICENSE)