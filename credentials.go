package gokeepasslib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

// DBCredentials holds the key used to lock and unlock the database
type DBCredentials struct {
	Key []byte
}

func (c *DBCredentials) String() string {
	return fmt.Sprintf("%x", c.Key)
}

func (c *DBCredentials) buildMasterKey(db *Database) ([]byte, error) {
	tmp := sha256.Sum256(c.Key)
	masterKey := tmp[:]

	block, err := aes.NewCipher(db.Headers.TransformSeed)
	if err != nil {
		return nil, err
	}

	// http://crypto.stackexchange.com/questions/21048/can-i-simulate-iterated-aes-ecb-with-other-block-cipher-modes
	for i := uint64(0); i < db.Headers.TransformRounds; i++ {
		result := make([]byte, 16)
		crypter := cipher.NewCBCEncrypter(block, result)
		crypter.CryptBlocks(masterKey[:16], masterKey[:16])
		crypter = cipher.NewCBCEncrypter(block, result)
		crypter.CryptBlocks(masterKey[16:], masterKey[16:])
	}

	tmp = sha256.Sum256(masterKey)
	masterKey = tmp[:]

	masterKey = append(db.Headers.MasterSeed, masterKey...)
	masterHash := sha256.Sum256(masterKey)
	masterKey = masterHash[:]

	return masterKey, nil
}

// NewPasswordCredentials builds new DBCredentials from a Password string
func NewPasswordCredentials(password string) *DBCredentials {
	credentials := new(DBCredentials)
	key := sha256.Sum256([]byte(password))
	credentials.Key = key[:]
	return credentials
}

// NewKeyCredentials builds new DBCredentials from a key file
func NewKeyCredentials(location string) (*DBCredentials, error) {
	credentials := new(DBCredentials)
	r, err := regexp.Compile("<data>(.+)<\\/data>")
	if err != nil {
		return nil, err
	}
	file, err := os.Open(location)
	if err != nil {
		return nil, err
	}
	var data []byte
	if data, err = ioutil.ReadAll(file); err != nil {
		return nil, err
	}

	if r.Match(data) {
		credentials.Key = r.FindSubmatch(data)[1]
	} else {
		key := sha256.Sum256(data)
		credentials.Key = key[:]
	}
	return credentials, nil
}
