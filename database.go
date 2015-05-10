package gokeepass_lib

import "fmt"

type Database struct {
	signature Signature
	headers   Headers
}

func (db *Database) String() string {
	return fmt.Sprintf("Database:\nSignature: %s\nHeaders: %s",
		db.signature,
		db.headers,
	)
}
