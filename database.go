package gokeepasslib

import (
	"crypto/sha256"
	"fmt"
)

//Stores all contents nessesary for a keepass database file
type Database struct {
	Signature   *FileSignature
	Headers     *FileHeaders
	Credentials *DBCredentials
	Content     *DBContent
}

//NewDatabase creates a new database with some sensable default settings. To create a database with no settigns per-set, use gokeepasslib.Database{}
func NewDatabase() *Database {
	db := new(Database)
	db.Signature = &DefaultSig
	db.Headers = NewFileHeaders()
	db.Credentials = new(DBCredentials)
	db.Content = NewDBContent()
	return db
}

func (db *Database) String() string {
	return fmt.Sprintf("Database:\nSignature: %s\n"+
		"Headers: %s\nCredentials: %s\nContent:\n%+v\n",
		db.Signature,
		db.Headers,
		db.Credentials,
		db.Content,
	)
}

/* Goes through entire database and encryptes any values in entries with protected=true set. 
 * This should be called after decoding if you want to view plaintext password in an entry
 * Warning: If you call this when entry values are already unlocked, it will cause them to be unreadable
 */
func (db *Database) UnlockProtectedEntries() {
	key := sha256.Sum256(db.Headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])
	salsaManager.UnlockGroups(db.Content.Root.Groups)
}

/* Goes through entire database and decryptes any values in entries with protected=true set. 
 * Warning: Do not call this if entries are already locked
 * Warning: Encoding a database calls LockProtectedEntries automatically
 */
func (db *Database) LockProtectedEntries() {
	key := sha256.Sum256(db.Headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])
	salsaManager.LockGroups(db.Content.Root.Groups)
}
