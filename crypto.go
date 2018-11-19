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

type CryptoStream interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

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

func UnlockProtectedGroups(p CryptoStream, gs []Group) {
	for i := range gs { //For each top level group
		UnlockProtectedGroup(p, &gs[i])
	}
}

func UnlockProtectedGroup(p CryptoStream, g *Group) {
	UnlockProtectedEntries(p, g.Entries)
	UnlockProtectedGroups(p, g.Groups)
}

func UnlockProtectedEntries(p CryptoStream, e []Entry) {
	for i := range e {
		UnlockProtectedEntry(p, &e[i])
	}
}

func UnlockProtectedEntry(p CryptoStream, e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = string(p.Unpack(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		UnlockProtectedEntries(p, e.Histories[i].Entries)
	}
}

func LockProtectedGroups(p CryptoStream, gs []Group) {
	for i := range gs {
		LockProtectedGroup(p, &gs[i])
	}
}

func LockProtectedGroup(p CryptoStream, g *Group) {
	LockProtectedEntries(p, g.Entries)
	LockProtectedGroups(p, g.Groups)
}

func LockProtectedEntries(p CryptoStream, es []Entry) {
	for i := range es {
		LockProtectedEntry(p, &es[i])
	}
}

func LockProtectedEntry(p CryptoStream, e *Entry) {
	for i := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = p.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		LockProtectedEntries(p, e.Histories[i].Entries)
	}
}
