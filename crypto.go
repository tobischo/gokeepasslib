package gokeepasslib

import (
	"github.com/tobischo/gokeepasslib/crypto"
)

// Constant enumerator for the inner random stream ID
const (
	NoStreamID    uint32 = 0
	ARC4StreamID         = 1
	SalsaStreamID        = 2
	ChaChaID             = 3
)

// CryptoStream is responsible for stream encrypting and decrypting of protected fields
type CryptoStream interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

// NewCryptoStream initialize a new CryptoStream
func NewCryptoStream(id uint32, key []byte) (CryptoStream, error) {
	switch id {
	case NoStreamID:
		return crypto.NewInsecureManager(), nil
	case SalsaStreamID:
		return crypto.NewSalsaManager(key)
	case ChaChaID:
		return crypto.NewChaChaManager(key)
	}
	return nil, nil
}

func unlockProtectedGroups(p CryptoStream, gs []Group) {
	for i := range gs { //For each top level group
		unlockProtectedGroup(p, &gs[i])
	}
}

func unlockProtectedGroup(p CryptoStream, g *Group) {
	unlockProtectedEntries(p, g.Entries)
	unlockProtectedGroups(p, g.Groups)
}

func unlockProtectedEntries(p CryptoStream, e []Entry) {
	for i := range e {
		unlockProtectedEntry(p, &e[i])
	}
}

func unlockProtectedEntry(p CryptoStream, e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = string(p.Unpack(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		unlockProtectedEntries(p, e.Histories[i].Entries)
	}
}

func lockProtectedGroups(p CryptoStream, gs []Group) {
	for i := range gs {
		lockProtectedGroup(p, &gs[i])
	}
}

func lockProtectedGroup(p CryptoStream, g *Group) {
	lockProtectedEntries(p, g.Entries)
	lockProtectedGroups(p, g.Groups)
}

func lockProtectedEntries(p CryptoStream, es []Entry) {
	for i := range es {
		lockProtectedEntry(p, &es[i])
	}
}

func lockProtectedEntry(p CryptoStream, e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = p.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		lockProtectedEntries(p, e.Histories[i].Entries)
	}
}
