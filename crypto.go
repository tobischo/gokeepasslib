package gokeepasslib

import (
	"bytes"
	"errors"

	"github.com/tobischo/gokeepasslib/v3/crypto"
)

// Constant enumerator for the inner random stream ID
const (
	NoStreamID     uint32 = 0 // ID for non-protection
	ARC4StreamID   uint32 = 1 // ID for ARC4 protection, not implemented
	SalsaStreamID  uint32 = 2 // ID for Salsa20 protection
	ChaChaStreamID uint32 = 3 // ID for ChaCha20 protection
)

// EncrypterManager is the manager to handle an Encrypter
type EncrypterManager struct {
	Encrypter Encrypter
}

// Encrypter is responsible for database encrypting and decrypting
type Encrypter interface {
	Decrypt(data []byte) []byte
	Encrypt(data []byte) []byte
}

// StreamManager is the manager to handle a Stream
type StreamManager struct {
	Stream Stream
}

// Stream is responsible for stream encrypting and decrypting of protected fields
type Stream interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

// NewEncrypterManager initialize a new EncrypterManager
func NewEncrypterManager(
	cipherID []byte,
	key []byte,
	iv []byte,
) (*EncrypterManager, error) {
	switch {
	case bytes.Equal(cipherID, CipherChaCha20):
		// ChaCha20
		encrypter, err := crypto.NewChaChaEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	case bytes.Equal(cipherID, CipherTwoFish):
		// TwoFish
		encrypter, err := crypto.NewTwoFishEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	case bytes.Equal(cipherID, CipherAES):
		// AES
		encrypter, err := crypto.NewAESEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	default:
		return nil, ErrUnsupportedEncrypterType
	}
}

// NewStreamManager initialize a new StreamManager
func NewStreamManager(id uint32, key []byte) (*StreamManager, error) {
	switch id {
	case NoStreamID:
		return &StreamManager{
			Stream: crypto.NewInsecureStream(),
		}, nil
	case SalsaStreamID:
		stream, err := crypto.NewSalsaStream(key)
		if err != nil {
			return nil, err
		}

		return &StreamManager{
			Stream: stream,
		}, nil
	case ChaChaStreamID:
		stream, err := crypto.NewChaChaStream(key)
		if err != nil {
			return nil, err
		}

		return &StreamManager{
			Stream: stream,
		}, nil
	default:
		return nil, ErrUnsupportedStreamType
	}
}

// Decrypt returns the decrypted data
func (em *EncrypterManager) Decrypt(data []byte) []byte {
	return em.Encrypter.Decrypt(data)
}

// Encrypt returns the encrypted data
func (em *EncrypterManager) Encrypt(data []byte) []byte {
	return em.Encrypter.Encrypt(data)
}

// Unpack returns the payload as unencrypted byte array
func (cs *StreamManager) Unpack(payload string) []byte {
	return cs.Stream.Unpack(payload)
}

// Pack returns the payload as encrypted string
func (cs *StreamManager) Pack(payload []byte) string {
	return cs.Stream.Pack(payload)
}

// UnlockProtectedGroups unlocks an array of protected groups
func (cs *StreamManager) UnlockProtectedGroups(gs []Group) {
	for i := range gs { // For each top level group
		cs.UnlockProtectedGroup(&gs[i])
	}
}

// UnlockProtectedGroup unlocks a protected group
func (cs *StreamManager) UnlockProtectedGroup(g *Group) {
	// Some KDBX files have groups defined before entries depending on the tool that
	// they were created with.
	// This also influences the locking order for the stream processing.
	// In order to correctly check the order we have to check based on the groupChildOrder value
	// this is set during unmarshalling
	if g.groupChildOrder == groupChildOrderGroupFirst {
		cs.UnlockProtectedGroups(g.Groups)
		cs.UnlockProtectedEntries(g.Entries)
	} else {
		cs.UnlockProtectedEntries(g.Entries)
		cs.UnlockProtectedGroups(g.Groups)
	}

	// unset groupChildOrder as for future marshalling the order in the struct superseeds
	// the order in the XML
	g.groupChildOrder = groupChildOrderDefault
}

// UnlockProtectedEntries unlocks an array of protected entries
func (cs *StreamManager) UnlockProtectedEntries(e []Entry) {
	for i := range e {
		cs.UnlockProtectedEntry(&e[i])
	}
}

// UnlockProtectedEntry unlocks a protected entry
func (cs *StreamManager) UnlockProtectedEntry(e *Entry) {
	for i := range e.Values {
		if e.Values[i].Value.Protected.Bool {
			e.Values[i].Value.Content = string(cs.Unpack(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		cs.UnlockProtectedEntries(e.Histories[i].Entries)
	}
}

// LockProtectedGroups locks an array of unprotected groups
func (cs *StreamManager) LockProtectedGroups(gs []Group) {
	for i := range gs {
		cs.LockProtectedGroup(&gs[i])
	}
}

// LockProtectedGroup locks an unprotected group
func (cs *StreamManager) LockProtectedGroup(g *Group) {
	cs.LockProtectedEntries(g.Entries)
	cs.LockProtectedGroups(g.Groups)
}

// LockProtectedEntries locks an array of unprotected entries
func (cs *StreamManager) LockProtectedEntries(es []Entry) {
	for i := range es {
		cs.LockProtectedEntry(&es[i])
	}
}

// LockProtectedEntry locks an unprotected entry
func (cs *StreamManager) LockProtectedEntry(e *Entry) {
	for i := range e.Values {
		if e.Values[i].Value.Protected.Bool {
			e.Values[i].Value.Content = cs.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		cs.LockProtectedEntries(e.Histories[i].Entries)
	}
}

// ErrUnsupportedEncrypterType is retured if no encrypter manager can be created
// due to an invalid length of EncryptionIV
var ErrUnsupportedEncrypterType = errors.New("Type of encrypter unsupported")

// ErrUnsupportedStreamType is retured if no stream manager can be created
// due to an unsupported InnerRandomStreamID value
var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")
