package gokeepasslib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrUnsupportedStreamType is retured if no streamManager can be created
// due to an unsupported InnerRandomStreamID value
var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")

// ErrRequiredAttributeMissing is returned if a required value is not given
type ErrRequiredAttributeMissing string

func (e ErrRequiredAttributeMissing) Error() string {
	return fmt.Sprintf("gokeepasslib: operation can not be performed if database does not have %s", e)
}

// Database stores all contents nessesary for a keepass database file
type Database struct {
	Signature   *FileSignature
	Headers     *FileHeaders
	Credentials *DBCredentials
	Content     *DBContent
}

// NewDatabase creates a new database with some sensable default settings. To create a database with no settigns per-set, use gokeepasslib.Database{}
func NewDatabase() *Database {
	return &Database{
		Signature:   &DefaultSig,
		Headers:     NewFileHeaders(),
		Credentials: new(DBCredentials),
		Content:     NewDBContent(),
	}
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

// StreamManager returns a ProtectedStreamManager bassed on the db headers, or nil if the type is unsupported
// Can be used to lock only certain entries instead of calling
func (db *Database) StreamManager() ProtectedStreamManager {
	if db.Headers == nil {
		return nil
	}
	switch db.Headers.InnerRandomStreamID {
	case NoStreamID:
		return new(InsecureStreamManager)
	case SalsaStreamID:
		key := sha256.Sum256(db.Headers.ProtectedStreamKey)
		return NewSalsaManager(key)
	default:
		return nil
	}
}

// UnlockProtectedEntries goes through the entire database and encrypts
// any Values in entries with protected=true set.
// This should be called after decoding if you want to view plaintext password in an entry
// Warning: If you call this when entry values are already unlocked, it will cause them to be unreadable
func (db *Database) UnlockProtectedEntries() error {
	manager := db.StreamManager()
	if manager == nil {
		return ErrUnsupportedStreamType
	}
	UnlockProtectedGroups(manager, db.Content.Root.Groups)
	return nil
}

// LockProtectedEntries goes through the entire database and decrypts
// any Values in entries with protected=true set.
// Warning: Do not call this if entries are already locked
// Warning: Encoding a database calls LockProtectedEntries automatically
func (db *Database) LockProtectedEntries() error {
	manager := db.StreamManager()
	if manager == nil {
		return ErrUnsupportedStreamType
	}
	LockProtectedGroups(manager, db.Content.Root.Groups)
	return nil
}

// Decrypter initializes a CBC decrypter for the database
func (db *Database) Decrypter() (cipher.BlockMode, error) {
	block, err := db.Cipher()
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCDecrypter(block, db.Headers.EncryptionIV), nil
}

// Encrypter initializes a CBC encrypter for the database
func (db *Database) Encrypter() (cipher.BlockMode, error) {
	if db.Headers == nil {
		return nil, ErrRequiredAttributeMissing("Headers")
	}
	if db.Headers.EncryptionIV == nil {
		return nil, ErrRequiredAttributeMissing("Headers.EncryptionIV")
	}
	block, err := db.Cipher()
	if err != nil {
		return nil, err
	}
	//Encrypts block data using AES block with initialization vector from header
	return cipher.NewCBCEncrypter(block, db.Headers.EncryptionIV), nil
}

// Cipher returns a new aes cipher initialized with the master key
func (db *Database) Cipher() (cipher.Block, error) {
	if db.Credentials == nil {
		return nil, ErrRequiredAttributeMissing("Credentials")
	}
	masterKey, err := db.Credentials.buildMasterKey(db)
	if err != nil {
		return nil, err
	}
	return aes.NewCipher(masterKey)
}

func (db *Database) buildHeaderHash() string {
	//Calculate hash
	buffer := bytes.NewBuffer(make([]byte, 0))

	db.Signature.WriteTo(buffer)
	buffer.Write(db.Headers.RawData)

	hash := sha256.Sum256([]byte(buffer.Bytes()))
	return base64.StdEncoding.EncodeToString(hash[:])
}
