package crypto

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"

	"github.com/aead/chacha20"
)

// ChaChaManager is a ChaCha20 cipher that implements CryptoStream interface
type ChaChaManager struct {
	cipher cipher.Stream
}

// NewChaChaManager initialize a new ChaChaManager interfaced with CryptoStream
func NewChaChaManager(key []byte) (*ChaChaManager, error) {
	hash := sha512.Sum512(key)

	cipher, err := chacha20.NewCipher(hash[32:44], hash[:32])
	if err != nil {
		return nil, err
	}

	c := ChaChaManager{
		cipher: cipher,
	}
	return &c, nil
}

func (c *ChaChaManager) Unpack(payload string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(payload)
	var data []byte
	data = make([]byte, len(decoded))

	c.cipher.XORKeyStream(data, []byte(decoded))
	return data
}

func (c *ChaChaManager) Pack(payload []byte) string {
	var data []byte
	data = make([]byte, len(payload))

	c.cipher.XORKeyStream(data, payload)
	str := base64.StdEncoding.EncodeToString(data)
	return str
}
