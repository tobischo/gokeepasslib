package gokeepasslib

import (
	"encoding/base64"

	"golang.org/x/crypto/salsa20"
)

var iv = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}

// SalsaManager is a structure holding the salsa key to lock and unlock
// protected entries.
type SalsaManager struct {
	key [32]byte
}

// NewSalsaManager returns an instance of SalsaManager
func NewSalsaManager(key [32]byte) SalsaManager {
	return SalsaManager{key}
}

// Unpack unlocks a given payload using the golang.org/x/crypto/salsa20 implementation
func (m SalsaManager) Unpack(payload string) []byte {
	in, _ := base64.StdEncoding.DecodeString(payload)
	out := make([]byte, len(in))
	salsa20.XORKeyStream(out, in, iv, &m.key)
	return out
}

// Pack locks a given payload using the golang.org/x/crypto/salsa20 implementation
func (m SalsaManager) Pack(payload []byte) string {
	out := make([]byte, len(payload))
	salsa20.XORKeyStream(out, payload, iv, &m.key)
	return base64.StdEncoding.EncodeToString(out)
}
