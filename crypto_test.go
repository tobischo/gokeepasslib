package gokeepasslib

import (
	"testing"
)

func TestInsecure(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte("test message")

	// Encrypt
	c, _ := NewCryptoStreamManager(NoStreamID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewCryptoStreamManager(NoStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode insecure: should be 'test message' not '%s'", decrypted)
	}
}

func TestChaCha(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte("test message")

	// Encrypt
	c, _ := NewCryptoStreamManager(ChaChaID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewCryptoStreamManager(ChaChaID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode chacha: should be 'test message' not '%s'", decrypted)
	}
}

func TestSalsa(t *testing.T) {
	key := make([]byte, 32)
	payload := []byte("test message")

	// Encrypt
	c, _ := NewCryptoStreamManager(ChaChaID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewCryptoStreamManager(ChaChaID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode salsa: should be 'test message' not '%s'", decrypted)
	}
}
