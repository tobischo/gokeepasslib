package gokeepasslib

import "fmt"

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
