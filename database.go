package gokeepasslib

import (
	"crypto/sha256"
	"fmt"
)

type Database struct {
	Signature   *FileSignature
	Headers     *FileHeaders
	Credentials *DBCredentials
	Content     *DBContent
}

func NewDatabase() *Database {
	return new(Database)
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

func (db *Database) UnlockProtectedEntries() {
	key := sha256.Sum256(db.Headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])
	salsaManager.UnlockGroups(db.Content.Root.Groups)
}

func (db *Database) LockProtectedEntries() {
	key := sha256.Sum256(db.Headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])

	salsaManager.LockGroups(db.Content.Root.Groups)
}
