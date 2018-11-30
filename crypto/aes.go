package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// AesEncrypter is an AES cipher that implements Encrypter interface
type AesEncrypter struct {
	block        cipher.Block
	encryptionIV []byte
}

// NewAesEncrypter initialize a new AesEncrypter interfaced with Encrypter
func NewAesEncrypter(key []byte, iv []byte) (*AesEncrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	e := AesEncrypter{
		block:        block,
		encryptionIV: iv,
	}
	return &e, nil
}

// Decrypt returns the decrypted data
func (ae *AesEncrypter) Decrypt(data []byte) []byte {
	ret := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(ae.block, ae.encryptionIV)
	mode.CryptBlocks(ret, data)
	return ret
}

// Encrypt returns the encrypted data
func (ae *AesEncrypter) Encrypt(data []byte) []byte {
	ret := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(ae.block, ae.encryptionIV)
	mode.CryptBlocks(ret, data)
	return ret
}
