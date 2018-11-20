package gokeepasslib

import (
	"errors"

	"github.com/tobischo/gokeepasslib/crypto"
)

// Constant enumerator for the inner random stream ID
const (
	NoStreamID     uint32 = 0
	ARC4StreamID          = 1
	SalsaStreamID         = 2
	ChaChaStreamID        = 3
)

// CryptoStreamManager is the manager to handle a CryptoStream
type CryptoStreamManager struct {
	Stream CryptoStream
}

// CryptoStream is responsible for stream encrypting and decrypting of protected fields
type CryptoStream interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

// NewCryptoStreamManager initialize a new CryptoStreamManager
func NewCryptoStreamManager(id uint32, key []byte) (manager *CryptoStreamManager, err error) {
	var stream CryptoStream
	manager = new(CryptoStreamManager)
	switch id {
	case NoStreamID:
		stream = crypto.NewInsecureStream()
	case SalsaStreamID:
		stream, err = crypto.NewSalsaStream(key)
	case ChaChaStreamID:
		stream, err = crypto.NewChaChaStream(key)
	default:
		return nil, ErrUnsupportedStreamType
	}
	manager.Stream = stream
	return
}

// Unpack returns the payload as unencrypted byte array
func (cs *CryptoStreamManager) Unpack(payload string) []byte {
	return cs.Stream.Unpack(payload)
}

// Pack returns the payload as encrypted string
func (cs *CryptoStreamManager) Pack(payload []byte) string {
	return cs.Stream.Pack(payload)
}

// UnlockProtectedGroups unlocks an array of protected groups
func (cs *CryptoStreamManager) UnlockProtectedGroups(gs []Group) {
	for i := range gs { //For each top level group
		cs.UnlockProtectedGroup(&gs[i])
	}
}

// UnlockProtectedGroup unlocks a protected group
func (cs *CryptoStreamManager) UnlockProtectedGroup(g *Group) {
	cs.UnlockProtectedEntries(g.Entries)
	cs.UnlockProtectedGroups(g.Groups)
}

// UnlockProtectedEntries unlocks an array of protected entries
func (cs *CryptoStreamManager) UnlockProtectedEntries(e []Entry) {
	for i := range e {
		cs.UnlockProtectedEntry(&e[i])
	}
}

// UnlockProtectedEntry unlocks a protected entry
func (cs *CryptoStreamManager) UnlockProtectedEntry(e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = string(cs.Unpack(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		cs.UnlockProtectedEntries(e.Histories[i].Entries)
	}
}

// LockProtectedGroups locks an array of unprotected groups
func (cs *CryptoStreamManager) LockProtectedGroups(gs []Group) {
	for i := range gs {
		cs.LockProtectedGroup(&gs[i])
	}
}

// LockProtectedGroup locks an unprotected group
func (cs *CryptoStreamManager) LockProtectedGroup(g *Group) {
	cs.LockProtectedEntries(g.Entries)
	cs.LockProtectedGroups(g.Groups)
}

// LockProtectedEntries locks an array of unprotected entries
func (cs *CryptoStreamManager) LockProtectedEntries(es []Entry) {
	for i := range es {
		cs.LockProtectedEntry(&es[i])
	}
}

// LockProtectedEntry locks an unprotected entry
func (cs *CryptoStreamManager) LockProtectedEntry(e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = cs.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		cs.LockProtectedEntries(e.Histories[i].Entries)
	}
}

// ErrUnsupportedStreamType is retured if no streamManager can be created
// due to an unsupported InnerRandomStreamID value
var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")
