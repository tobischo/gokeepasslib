package gokeepasslib

import (
	"crypto/sha256"
	"fmt"
)

type Database struct {
	signature   Signature
	headers     Headers
	credentials *Credentials
	content     *Content
}

func (db *Database) String() string {
	return fmt.Sprintf("Database:\nSignature: %s\n"+
		"Headers: %s\nCredentials: %s\nContent:\n%+v\n",
		db.signature,
		db.headers,
		db.credentials,
		db.content,
	)
}

func (db *Database) UnlockProtectedEntries() {
	key := sha256.Sum256(db.headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])

	salsaManager.unlockProtectedEntries(db.content.Root.Groups)
}
