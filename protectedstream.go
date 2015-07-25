package gokeepasslib

import (
	"errors"
)

var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")

type ProtectedStreamManager interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

// InsecureStreamManager is a stream manger which does not encrypt, just stores the plaintext payload
type InsecureStreamManager struct{}

func (i InsecureStreamManager) Unpack(payload string) []byte {
	return []byte(payload)
}
func (i InsecureStreamManager) Pack(payload []byte) string {
	return string(payload)
}

func UnlockProtectedGroups(p ProtectedStreamManager, gs []Group) {
	for i, _ := range gs { //For each top level group
		UnlockProtectedGroup(p, &gs[i])
	}
}
func UnlockProtectedGroup(p ProtectedStreamManager, g *Group) {
	UnlockProtectedEntries(p, g.Entries)
	UnlockProtectedGroups(p, g.Groups)
}
func UnlockProtectedEntries(p ProtectedStreamManager, e []Entry) {
	for i, _ := range e {
		UnlockProtectedEntry(p, &e[i])
	}
}
func UnlockProtectedEntry(p ProtectedStreamManager, e *Entry) {
	for i, _ := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = string(p.Unpack(e.Values[i].Value.Content))
		}
	}
	for i, _ := range e.Histories {
		UnlockProtectedEntries(p, e.Histories[i].Entries)
	}
}

func LockProtectedGroups(p ProtectedStreamManager, gs []Group) {
	for i, _ := range gs {
		LockProtectedGroup(p, &gs[i])
	}
}
func LockProtectedGroup(p ProtectedStreamManager, g *Group) {
	LockProtectedEntries(p, g.Entries)
	LockProtectedGroups(p, g.Groups)
}
func LockProtectedEntries(p ProtectedStreamManager, es []Entry) {
	for i, _ := range es {
		LockProtectedEntry(p, &es[i])
	}
}
func LockProtectedEntry(p ProtectedStreamManager, e *Entry) {
	for i, _ := range e.Values {
		if bool(e.Values[i].Value.Protected) {
			e.Values[i].Value.Content = p.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i, _ := range e.Histories {
		UnlockProtectedEntries(p, e.Histories[i].Entries)
	}
}
