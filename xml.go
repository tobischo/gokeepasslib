package gokeepasslib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// ErrInvalidUUIDLength is an error which is returned during unmarshaling if the UUID does not have 16 bytes length
var ErrInvalidUUIDLength = errors.New("gokeepasslib: length of decoded UUID was not 16")

// UUID stores a universal identifier for each group+entry
type UUID [16]byte

// NewUUID returns a new randomly generated UUID
func NewUUID() UUID {
	var id UUID
	rand.Read(id[:])
	return id
}

// Compare allowes to check whether two instance of UUID are equal in value.
// This is used for searching a uuid
func (u UUID) Compare(c UUID) bool {
	for i, v := range c {
		if u[i] != v {
			return false
		}
	}
	return true
}

// MarshalText is a marshaler method to encode uuid content as base 64 and return it
func (u UUID) MarshalText() ([]byte, error) {
	text := make([]byte, 24)
	base64.StdEncoding.Encode(text, u[:])
	return text, nil
}

// UnmarshalText unmarshals a byte slice into a UUID by decoding the given data from base64
func (u *UUID) UnmarshalText(text []byte) error {
	id := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	length, err := base64.StdEncoding.Decode(id, text)
	if err != nil {
		return err
	}
	if length != 16 {
		return ErrInvalidUUIDLength
	}
	copy((*u)[:], id[:16])
	return nil
}

// MemProtection is a structure containing settings for MemoryProtection
type MemProtection struct {
	ProtectTitle    w.BoolWrapper `xml:"ProtectTitle"`
	ProtectUserName w.BoolWrapper `xml:"ProtectUserName"`
	ProtectPassword w.BoolWrapper `xml:"ProtectPassword"`
	ProtectURL      w.BoolWrapper `xml:"ProtectURL"`
	ProtectNotes    w.BoolWrapper `xml:"ProtectNotes"`
}

type RootDataOption func(*RootData)

func WithRootDataFormattedTime(formatted bool) RootDataOption {
	return func(rd *RootData) {
		for _, group := range rd.Groups {
			WithGroupFormattedTime(formatted)(&group)
		}
	}
}

// RootData stores the actual content of a database (all enteries sorted into groups and the recycle bin)
type RootData struct {
	Groups         []Group             `xml:"Group"`
	DeletedObjects []DeletedObjectData `xml:"DeletedObjects>DeletedObject"`
}

// NewRootData returns a RootData struct with good defaults
func NewRootData(options ...RootDataOption) *RootData {
	root := new(RootData)
	group := NewGroup()
	group.Name = "NewDatabase"
	entry := NewEntry()
	entry.Values = append(entry.Values, ValueData{Key: "Title", Value: V{Content: "Sample Entry"}})
	group.Entries = append(group.Entries, entry)
	root.Groups = append(root.Groups, group)

	for _, option := range options {
		option(root)
	}

	return root
}

func (rd *RootData) setKdbxFormatVersion(version formatVersion) {
	for i := range rd.Groups {
		(&rd.Groups[i]).setKdbxFormatVersion(version)
	}

	for i := range rd.DeletedObjects {
		(&rd.DeletedObjects[i]).setKdbxFormatVersion(version)
	}
}

type EntryOption func(*Entry)

func WithEntryFormattedTime(formatted bool) EntryOption {
	return func(e *Entry) {
		WithTimeDataFormattedTime(formatted)(&e.Times)
	}
}

// Entry is the structure which holds information about a parsed entry in a keepass database
type Entry struct {
	UUID            UUID              `xml:"UUID"`
	IconID          int64             `xml:"IconID"`
	ForegroundColor string            `xml:"ForegroundColor"`
	BackgroundColor string            `xml:"BackgroundColor"`
	OverrideURL     string            `xml:"OverrideURL"`
	Tags            string            `xml:"Tags"`
	Times           TimeData          `xml:"Times"`
	Values          []ValueData       `xml:"String,omitempty"`
	AutoType        AutoTypeData      `xml:"AutoType"`
	Histories       []History         `xml:"History"`
	Binaries        []BinaryReference `xml:"Binary,omitempty"`
}

// NewEntry return a new entry with time data and uuid set
func NewEntry(options ...EntryOption) Entry {
	entry := Entry{}
	entry.Times = NewTimeData()
	entry.UUID = NewUUID()

	for _, option := range options {
		option(&entry)
	}

	return entry
}

func (e *Entry) setKdbxFormatVersion(version formatVersion) {
	(&e.Times).setKdbxFormatVersion(version)

	for i := range e.Histories {
		(&e.Histories[i]).setKdbxFormatVersion(version)
	}
}

// Get returns the value in e corresponding with key k, or an empty string otherwise
func (e *Entry) Get(key string) *ValueData {
	for i := range e.Values {
		if e.Values[i].Key == key {
			return &e.Values[i]
		}
	}
	return nil
}

// GetContent returns the content of the value belonging to the given key in string form
func (e *Entry) GetContent(key string) string {
	val := e.Get(key)
	if val == nil {
		return ""
	}
	return val.Value.Content
}

// GetIndex returns the index of the Value belonging to the given key, or -1 if none is found
func (e *Entry) GetIndex(key string) int {
	for i := range e.Values {
		if e.Values[i].Key == key {
			return i
		}
	}
	return -1
}

// GetPassword returns the password of an entry
func (e *Entry) GetPassword() string {
	return e.GetContent("Password")
}

// GetPasswordIndex returns the index in the values slice belonging to the password
func (e *Entry) GetPasswordIndex() int {
	return e.GetIndex("Password")
}

// GetTitle returns the title of an entry
func (e *Entry) GetTitle() string {
	return e.GetContent("Title")
}

// History stores information about changes made to an entry,
// in the form of a list of previous versions of that entry
type History struct {
	Entries []Entry `xml:"Entry"`
}

func (h *History) setKdbxFormatVersion(version formatVersion) {
	for i := range h.Entries {
		(&h.Entries[i]).setKdbxFormatVersion(version)
	}
}

// ValueData is a structure containing key value pairs of information stored in an entry
type ValueData struct {
	Key   string `xml:"Key"`
	Value V      `xml:"Value"`
}

// V is a wrapper for the content of a value, so that it can store whether it is protected
type V struct {
	Content   string        `xml:",chardata"`
	Protected w.BoolWrapper `xml:"Protected,attr,omitempty"`
}

// AutoTypeData is a structure containing auto type settings of an entry
type AutoTypeData struct {
	Enabled                 w.BoolWrapper        `xml:"Enabled"`
	DataTransferObfuscation int64                `xml:"DataTransferObfuscation"`
	Association             *AutoTypeAssociation `xml:"Association,omitempty"`
}

// AutoTypeAssociation is a structure that store the keystroke sequence of a window for AutoTypeData
type AutoTypeAssociation struct {
	Window            string `xml:"Window"`
	KeystrokeSequence string `xml:"KeystrokeSequence"`
}

// CustomData is the structure for plugins custom data
type CustomData struct {
	XMLName xml.Name `xml:"Item"`
	Key     string   `xml:"Key"`
	Value   string   `xml:"Value"`
}
