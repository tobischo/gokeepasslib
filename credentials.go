package gokeepasslib

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"

	"github.com/aead/argon2"
)

// DBCredentials holds the key used to lock and unlock the database
type DBCredentials struct {
	Passphrase []byte // Passphrase if using one, stored in sha256 hash
	Key        []byte // Contents of the keyfile if using one, stored in sha256 hash
	Windows    []byte // Whatever is returned from windows user account auth, stored in sha256 hash
}

func (c *DBCredentials) buildCompositeKey() ([]byte, error) {
	hash := sha256.New()
	if c.Passphrase != nil { // If the hashed password is provided
		_, err := hash.Write(c.Passphrase)
		if err != nil {
			return nil, err
		}
	}
	if c.Key != nil { // If the hashed keyfile is provided
		_, err := hash.Write(c.Key)
		if err != nil {
			return nil, err
		}
	}
	if c.Windows != nil { // If the hashed password is provided
		_, err := hash.Write(c.Windows)
		if err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func (c *DBCredentials) buildTransformedKey(db *Database) ([]byte, error) {
	transformedKey, err := c.buildCompositeKey()
	if err != nil {
		return nil, err
	}

	if db.Header.IsKdbx4() {
		if reflect.DeepEqual(db.Header.FileHeaders.KdfParameters.UUID, KdfArgon2) {
			// Argon 2
			transformedKey = argon2.Key2d(
				transformedKey, // Master key
				db.Header.FileHeaders.KdfParameters.Salt[:],             // Salt
				uint32(db.Header.FileHeaders.KdfParameters.Iterations),  // Time cost
				uint32(db.Header.FileHeaders.KdfParameters.Memory)/1024, // Memory cost
				uint8(db.Header.FileHeaders.KdfParameters.Parallelism),  // Parallelism
				32, // Hash length
			)
		} else {
			// AES
			key, err := cryptAESKey(
				transformedKey,
				db.Header.FileHeaders.KdfParameters.Salt[:],
				db.Header.FileHeaders.KdfParameters.Rounds,
			)
			if err != nil {
				return nil, err
			}
			transformedKey = key[:]
		}
	} else {
		// AES
		key, err := cryptAESKey(
			transformedKey,
			db.Header.FileHeaders.TransformSeed,
			db.Header.FileHeaders.TransformRounds,
		)
		if err != nil {
			return nil, err
		}
		transformedKey = key[:]
	}
	return transformedKey, nil
}

func buildMasterKey(db *Database, transformedKey []byte) []byte {
	masterKey := sha256.New()
	masterKey.Write(db.Header.FileHeaders.MasterSeed)
	masterKey.Write(transformedKey)
	return masterKey.Sum(nil)
}

func buildHmacKey(db *Database, transformedKey []byte) []byte {
	masterKey := sha512.New()
	masterKey.Write(db.Header.FileHeaders.MasterSeed)
	masterKey.Write(transformedKey)
	masterKey.Write([]byte{0x01})
	hmacKey := sha512.New()
	hmacKey.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	hmacKey.Write(masterKey.Sum(nil))
	return hmacKey.Sum(nil)
}

func cryptAESKey(masterKey []byte, seed []byte, rounds uint64) ([]byte, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}

	newKey := make([]byte, len(masterKey))
	copy(newKey, masterKey)

	for i := uint64(0); i < rounds; i++ {
		block.Encrypt(newKey, newKey)
		block.Encrypt(newKey[16:], newKey[16:])
	}

	hash := sha256.Sum256(newKey)
	return hash[:], nil
}

// NewPasswordCredentials builds a new DBCredentials from a Password string
func NewPasswordCredentials(password string) *DBCredentials {
	hashedpw := sha256.Sum256([]byte(password))
	return &DBCredentials{Passphrase: hashedpw[:]}
}

// ParseKeyFile returns the hashed key from a key file at the path specified by location, parsing xml if needed
func ParseKeyFile(location string) ([]byte, error) {
	file, err := os.Open(location)
	if err != nil {
		return nil, err
	}

	var data []byte
	if data, err = ioutil.ReadAll(file); err != nil {
		return nil, err
	}

	return ParseKeyData(data)
}

type xmlKeyFileData struct {
	XMLName xml.Name       `xml:"KeyFile"`
	Meta    xmlKeyFileMeta `xml:"Meta"`
	Key     xmlKeyFileKey  `xml:"Key"`
}

type xmlKeyFileMeta struct {
	Version string `xml:"Version"`
}

type xmlKeyFileKey struct {
	Data xmlKeyFileKeyData `xml:"Data"`
}

type xmlKeyFileKeyData struct {
	Hash  string `xml:"Hash,attr"`
	Value []byte `xml:",innerxml"`
}

var whiteSpacePattern = regexp.MustCompile(`\s+`)

const xmlKeyDataHashLength = 4

// ParseKeyData returns the hashed key from a key file in bytes, parsing xml if needed
func ParseKeyData(data []byte) ([]byte, error) {
	// Check if the provided file is an XML key file
	// errInvalidKeyFileXML is returned if it was not actually parseable xml data
	decodedKey, err := parseXMLKeyFileData(data)
	if err != errInvalidKeyFileXML {
		return decodedKey, err
	}

	// If the key is exactly 32 byte it is assumed to already be in the correct format
	if len(data) == 32 {
		return data, nil
	}

	// If the key is 64 byte as a hex string, it should be decoded into 32 byte
	// If this does not work, it is not a hex string
	// In that case we have to default to simply hashing the body
	if len(data) == 64 {
		decodedHex, err := hex.DecodeString(string(data))
		if err == nil {
			return decodedHex, nil
		}
	}

	hashedKey := sha256.Sum256(data)
	return hashedKey[:], nil
}

var errInvalidKeyFileXML = errors.New("invalid key file XML")
var errKeyHashMismatch = errors.New("key hash mismatch")

func parseXMLKeyFileData(data []byte) ([]byte, error) {
	keyFileData := xmlKeyFileData{}
	err := xml.Unmarshal(data, &keyFileData)
	if err != nil {
		return nil, errInvalidKeyFileXML
	}

	keyFileData.Key.Data.Value = whiteSpacePattern.ReplaceAll(keyFileData.Key.Data.Value, []byte(``))

	switch keyFileData.Meta.Version {
	// 1.00 has to be supported as it is used in some older versions of keepass
	case "1.00", "1.0":
		return parseV1XMLKeyFileData(keyFileData.Key.Data.Value)
	case "2.0":
		return parseV2XMLKeyFileData(keyFileData.Key.Data.Value, keyFileData.Key.Data.Hash)
	default:
		return nil, fmt.Errorf("Unsupported key file XML format %s", keyFileData.Meta.Version)
	}
}

func parseV1XMLKeyFileData(data []byte) ([]byte, error) {
	// v1 keyfile data should just be base64 encoded content
	decodedKey := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	if _, err := base64.StdEncoding.Decode(decodedKey, data); err != nil {
		return nil, err
	}

	if len(decodedKey) < 32 {
		return decodedKey, nil
	}

	// Slice necessary due to padding at the end of the hash
	return decodedKey[:32], nil
}

func parseV2XMLKeyFileData(data []byte, hash string) ([]byte, error) {
	decodedHexKey, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256(decodedHexKey)
	keyHashPart := fmt.Sprintf("%X", keyHash[:xmlKeyDataHashLength])

	if keyHashPart != hash {
		return nil, errKeyHashMismatch
	}

	return decodedHexKey, err
}

// NewKeyCredentials builds a new DBCredentials from a key file at the path specified by location
func NewKeyCredentials(location string) (*DBCredentials, error) {
	key, err := ParseKeyFile(location)
	if err != nil {
		return nil, err
	}

	return &DBCredentials{Key: key}, nil
}

// NewKeyDataCredentials builds a new DBCredentials from a key file in bytes
func NewKeyDataCredentials(data []byte) (*DBCredentials, error) {
	key, err := ParseKeyData(data)
	if err != nil {
		return nil, err
	}

	return &DBCredentials{Key: key}, nil
}

// NewPasswordAndKeyCredentials builds a new DBCredentials from a password and the key file at the path specified by location
func NewPasswordAndKeyCredentials(password, location string) (*DBCredentials, error) {
	key, err := ParseKeyFile(location)
	if err != nil {
		return nil, err
	}

	hashedpw := sha256.Sum256([]byte(password))

	return &DBCredentials{
		Passphrase: hashedpw[:],
		Key:        key,
	}, nil
}

// NewPasswordAndKeyDataCredentials builds a new DBCredentials from a password and the key file in bytes
func NewPasswordAndKeyDataCredentials(password string, data []byte) (*DBCredentials, error) {
	key, err := ParseKeyData(data)
	if err != nil {
		return nil, err
	}

	hashedpw := sha256.Sum256([]byte(password))

	return &DBCredentials{
		Passphrase: hashedpw[:],
		Key:        key,
	}, nil
}

func (c *DBCredentials) String() string {
	return fmt.Sprintf(
		"Hashed Passphrase: %x\nHashed Key: %x\nHashed Windows Auth: %x",
		c.Passphrase,
		c.Key,
		c.Windows,
	)
}
