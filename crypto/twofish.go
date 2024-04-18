package crypto

import (
	"crypto/cipher"

	"golang.org/x/crypto/twofish" //nolint:staticcheck
)

// TwoFishEncrypter is a TwoFish cipher that implements Encrypter interface
type TwoFishEncrypter struct {
	block        cipher.Block
	encryptionIV []byte
}

// NewTwoFishEncrypter initialize a new TwoFishEncrypter interfaced with Encrypter
func NewTwoFishEncrypter(key []byte, iv []byte) (*TwoFishEncrypter, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	e := TwoFishEncrypter{
		block:        block,
		encryptionIV: iv,
	}
	return &e, nil
}

// Decrypt returns the decrypted data
func (tfe *TwoFishEncrypter) Decrypt(data []byte) []byte {
	ret := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(tfe.block, tfe.encryptionIV)
	mode.CryptBlocks(ret, data)
	return ret
}

// Encrypt returns the encrypted data
func (tfe *TwoFishEncrypter) Encrypt(data []byte) []byte {
	ret := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(tfe.block, tfe.encryptionIV)
	mode.CryptBlocks(ret, data)
	return ret
}
