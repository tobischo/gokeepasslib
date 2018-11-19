package gokeepasslib

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

type Database struct {
	Options     *DBOptions
	Credentials *DBCredentials
	Header      *DBHeader
	Hashes      *DBHashes
	Content     *DBContent
}

type DBOptions struct {
	ValidateHashes bool
}

func NewDatabase() *Database {
	header := NewHeader()
	return &Database{
		Options:     NewOptions(),
		Credentials: new(DBCredentials),
		Header:      header,
		Hashes:      NewHashes(header),
		Content:     NewContent(),
	}
}

func NewOptions() *DBOptions {
	return &DBOptions{
		ValidateHashes: true,
	}
}

// Get transformed key from Credentials
func (db *Database) getTransformedKey() ([]byte, error) {
	if db.Credentials == nil {
		return nil, ErrRequiredAttributeMissing("Credentials")
	}
	return db.Credentials.buildTransformedKey(db)
}

// Decrypter initializes a CBC decrypter for the database
func (db *Database) Decrypter(transformedKey []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(buildMasterKey(db, transformedKey))
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCDecrypter(block, db.Header.FileHeaders.EncryptionIV), nil
}

// Encrypter initializes a CBC encrypter for the database
func (db *Database) Encrypter(transformedKey []byte) (cipher.BlockMode, error) {
	if db.Header == nil {
		return nil, ErrRequiredAttributeMissing("Header")
	}
	if db.Header.FileHeaders == nil {
		return nil, ErrRequiredAttributeMissing("Header.FileHeaders")
	}
	if db.Header.FileHeaders.EncryptionIV == nil {
		return nil, ErrRequiredAttributeMissing("Header.FileHeaders.EncryptionIV")
	}
	block, err := aes.NewCipher(buildMasterKey(db, transformedKey))
	if err != nil {
		return nil, err
	}
	//Encrypts block data using AES block with initialization vector from header
	return cipher.NewCBCEncrypter(block, db.Header.FileHeaders.EncryptionIV), nil
}

// StreamManager returns a ProtectedStreamManager bassed on the db headers, or nil if the type is unsupported
// Can be used to lock only certain entries instead of calling
func (db *Database) CryptoStreamManager() (CryptoStream, error) {
	if db.Header.FileHeaders != nil {
		if db.Header.IsKdbx4() {
			return NewCryptoStream(db.Content.InnerHeader.InnerRandomStreamID, db.Content.InnerHeader.InnerRandomStreamKey)
		} else {
			return NewCryptoStream(db.Header.FileHeaders.InnerRandomStreamID, db.Header.FileHeaders.ProtectedStreamKey)
		}
	}
	return nil, nil
}

// UnlockProtectedEntries goes through the entire database and encrypts
// any Values in entries with protected=true set.
// This should be called after decoding if you want to view plaintext password in an entry
// Warning: If you call this when entry values are already unlocked, it will cause them to be unreadable
func (db *Database) UnlockProtectedEntries() error {
	manager, err := db.CryptoStreamManager()
	if err != nil {
		return err
	}
	if manager == nil {
		return ErrUnsupportedStreamType
	}
	unlockProtectedGroups(manager, db.Content.Root.Groups)
	return nil
}

// LockProtectedEntries goes through the entire database and decrypts
// any Values in entries with protected=true set.
// Warning: Do not call this if entries are already locked
// Warning: Encoding a database calls LockProtectedEntries automatically
func (db *Database) LockProtectedEntries() error {
	manager, err := db.CryptoStreamManager()
	if err != nil {
		return err
	}
	if manager == nil {
		return ErrUnsupportedStreamType
	}
	lockProtectedGroups(manager, db.Content.Root.Groups)
	return nil
}

// ErrUnsupportedStreamType is retured if no streamManager can be created
// due to an unsupported InnerRandomStreamID value
var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")

// ErrRequiredAttributeMissing is returned if a required value is not given
type ErrRequiredAttributeMissing string

func (e ErrRequiredAttributeMissing) Error() string {
	return fmt.Sprintf("gokeepasslib: operation can not be performed if database does not have %s", e)
}
