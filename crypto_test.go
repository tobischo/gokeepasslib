package gokeepasslib

import (
	"testing"
)

const testMessage = "test message"

func TestInsecure(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte(testMessage)

	// Encrypt
	c, _ := NewStreamManager(NoStreamID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(NoStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != testMessage {
		t.Fatalf("Failed to decode insecure: should be 'test message' not '%s'", decrypted)
	}
}

func TestChaCha(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte(testMessage)

	// Encrypt
	c, err := NewStreamManager(ChaChaStreamID, key)
	if err != nil {
		t.Fatalf("Failed to create stream manager: %v", err)
	}
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(ChaChaStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode chacha: should be 'test message' not '%s'", decrypted)
	}
}

func TestSalsa(t *testing.T) {
	key := make([]byte, 32)
	payload := []byte("test message")

	// Encrypt
	c, _ := NewStreamManager(SalsaStreamID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(SalsaStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode salsa: should be 'test message' not '%s'", decrypted)
	}
}
