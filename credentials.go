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
	Passphrase []byte //Passphrase if using one, stored in sha256 hash
	Key        []byte //Contents of the keyfile if using one, stored in sha256 hash
	Windows    []byte //Whatever is returned from windows user account auth, stored in sha256 hash
}

func (c *DBCredentials) String() string {
	return fmt.Sprintf("Hashed Passphrase: %x\nHashed Key: %x\nHashed Windows Auth: %x", c.Passphrase, c.Key, c.Windows)
}

func (c *DBCredentials) buildCompositeKey() ([]byte, error) {
	hash := sha256.New()
	if c.Passphrase != nil { //If the hashed password is provided
		_, err := hash.Write(c.Passphrase)
		if err != nil {
			return nil, err
		}
	}
	if c.Key != nil { //If the hashed keyfile is provided
		_, err := hash.Write(c.Key)
		if err != nil {
			return nil, err
		}
	}
	if c.Windows != nil { //If the hashed password is provided
		_, err := hash.Write(c.Windows)
		if err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func (c *DBCredentials) buildMasterKey(db *Database) ([]byte, error) {
	masterKey, err := c.buildCompositeKey()
	if err != nil {
		return nil, err
	}

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

	tmp := sha256.Sum256(masterKey)
	masterKey = tmp[:]

	masterKey = append(db.Headers.MasterSeed, masterKey...)
	masterHash := sha256.Sum256(masterKey)
	masterKey = masterHash[:]

	return masterKey, nil
}

//NewPasswordCredentials builds a new DBCredentials from a Password string
func NewPasswordCredentials(password string) *DBCredentials {
	hashed := sha256.Sum256([]byte(password))
	return &DBCredentials{Passphrase: hashed[:]}
}

//ParseKeyFile returns the hashed key from a key file at the path specified by location, parsing xml if needed
func ParseKeyFile(location string) ([]byte, error) {
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
	if r.Match(data) { //If keyfile is in xml form, extract key data
		data = r.FindSubmatch(data)[1]
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

//NewKeyCredentials builds new DBCredentials from a key file at the path specified by location
func NewKeyCredentials(location string) (*DBCredentials, error) {
	key, err := ParseKeyFile(location)
	if err != nil {
		return nil, err
	}
	return &DBCredentials{Key: key}, nil
}

//NewPasswordAndKeyCredentials builds new DBCredentials from a password and the key file at the path specified by location
func NewPasswordAndKeyCredentials(password, location string) (*DBCredentials, error) {
	credentials, err := NewKeyCredentials(location)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256([]byte(password))
	credentials.Passphrase = hashed[:]

	return credentials, nil
}
