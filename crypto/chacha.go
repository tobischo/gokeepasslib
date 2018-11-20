package crypto

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"

	"github.com/aead/chacha20"
)

// ChaChaStream is a ChaCha20 cipher that implements CryptoStream interface
type ChaChaStream struct {
	cipher cipher.Stream
}

// NewChaChaStream initialize a new ChaChaStream interfaced with CryptoStream
func NewChaChaStream(key []byte) (*ChaChaStream, error) {
	hash := sha512.Sum512(key)

	cipher, err := chacha20.NewCipher(hash[32:44], hash[:32])
	if err != nil {
		return nil, err
	}

	c := ChaChaStream{
		cipher: cipher,
	}
	return &c, nil
}

// Unpack returns the payload as unencrypted byte array
func (c *ChaChaStream) Unpack(payload string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(payload)

	data := make([]byte, len(decoded))
	c.cipher.XORKeyStream(data, decoded)
	return data
}

// Pack returns the payload as encrypted string
func (c *ChaChaStream) Pack(payload []byte) string {
	data := make([]byte, len(payload))

	c.cipher.XORKeyStream(data, payload)
	str := base64.StdEncoding.EncodeToString(data)
	return str
}
