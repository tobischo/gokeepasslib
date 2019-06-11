package gokeepasslib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"

	w "github.com/tobischo/gokeepasslib/v2/wrappers"
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

// MetaData is the structure for the metadata headers at the top of kdbx files,
// it contains things like the name of the database
type MetaData struct {
	Generator                  string         `xml:"Generator"`
	HeaderHash                 string         `xml:"HeaderHash"`
	DatabaseName               string         `xml:"DatabaseName"`
	DatabaseNameChanged        *w.TimeWrapper `xml:"DatabaseNameChanged"`
	DatabaseDescription        string         `xml:"DatabaseDescription"`
	DatabaseDescriptionChanged *w.TimeWrapper `xml:"DatabaseDescriptionChanged"`
	DefaultUserName            string         `xml:"DefaultUserName"`
	DefaultUserNameChanged     *w.TimeWrapper `xml:"DefaultUserNameChanged"`
	MaintenanceHistoryDays     int64          `xml:"MaintenanceHistoryDays"`
	Color                      string         `xml:"Color"`
	MasterKeyChanged           *w.TimeWrapper `xml:"MasterKeyChanged"`
	MasterKeyChangeRec         int64          `xml:"MasterKeyChangeRec"`
	MasterKeyChangeForce       int64          `xml:"MasterKeyChangeForce"`
	MemoryProtection           MemProtection  `xml:"MemoryProtection"`
	RecycleBinEnabled          w.BoolWrapper  `xml:"RecycleBinEnabled"`
	RecycleBinUUID             UUID           `xml:"RecycleBinUUID"`
	RecycleBinChanged          *w.TimeWrapper `xml:"RecycleBinChanged"`
	EntryTemplatesGroup        string         `xml:"EntryTemplatesGroup"`
	EntryTemplatesGroupChanged *w.TimeWrapper `xml:"EntryTemplatesGroupChanged"`
	HistoryMaxItems            int64          `xml:"HistoryMaxItems"`
	HistoryMaxSize             int64          `xml:"HistoryMaxSize"`
	LastSelectedGroup          string         `xml:"LastSelectedGroup"`
	LastTopVisibleGroup        string         `xml:"LastTopVisibleGroup"`
	Binaries                   Binaries       `xml:"Binaries>Binary"`
	CustomData                 []CustomData   `xml:"CustomData>Item"`
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

// DeletedObjectData is the structure for a deleted object
type DeletedObjectData struct {
	XMLName      xml.Name       `xml:"DeletedObject"`
	UUID         UUID           `xml:"UUID"`
	DeletionTime *w.TimeWrapper `xml:"DeletionTime"`
}

// CustomData is the structure for plugins custom data
type CustomData struct {
	XMLName xml.Name `xml:"Item"`
	Key     string   `xml:"Key"`
	Value   string   `xml:"Value"`
}

type MetaDataOption func(*MetaData)

func WithMetaDataFormattedTime(formatted bool) MetaDataOption {
	return func(md *MetaData) {
		md.MasterKeyChanged.Formatted = formatted
	}
}

// NewMetaData creates a MetaData struct with some defaults set
func NewMetaData(options ...MetaDataOption) *MetaData {
	now := w.Now()

	md := &MetaData{
		MasterKeyChanged:       &now,
		MasterKeyChangeRec:     -1,
		MasterKeyChangeForce:   -1,
		HistoryMaxItems:        10,
		HistoryMaxSize:         6291456, // 6 MB
		MaintenanceHistoryDays: 365,
	}

	for _, option := range options {
		option(md)
	}

	return md
}

type GroupOption func(*Group)

func WithGroupFormattedTime(formatted bool) GroupOption {
	return func(g *Group) {
		WithTimeDataFormattedTime(formatted)(&g.Times)

		for _, group := range g.Groups {
			WithGroupFormattedTime(formatted)(&group)
		}

		for _, entry := range g.Entries {
			WithEntryFormattedTime(formatted)(&entry)
		}
	}
}

// Group is a structure to store entries in their named groups for organization
type Group struct {
	UUID                    UUID          `xml:"UUID"`
	Name                    string        `xml:"Name"`
	Notes                   string        `xml:"Notes"`
	IconID                  int64         `xml:"IconID"`
	Times                   TimeData      `xml:"Times"`
	IsExpanded              w.BoolWrapper `xml:"IsExpanded"`
	DefaultAutoTypeSequence string        `xml:"DefaultAutoTypeSequence"`
	EnableAutoType          w.BoolWrapper `xml:"EnableAutoType"`
	EnableSearching         w.BoolWrapper `xml:"EnableSearching"`
	LastTopVisibleEntry     string        `xml:"LastTopVisibleEntry"`
	Entries                 []Entry       `xml:"Entry,omitempty"`
	Groups                  []Group       `xml:"Group,omitempty"`
}

// NewGroup returns a new group with time data and uuid set
func NewGroup(options ...GroupOption) Group {
	group := Group{
		EnableAutoType:  w.BoolWrapper(true),
		EnableSearching: w.BoolWrapper(true),
		Times:           NewTimeData(),
		UUID:            NewUUID(),
	}

	for _, option := range options {
		option(&group)
	}

	return group
}

type TimeDataOption func(*TimeData)

func WithTimeDataFormattedTime(formatted bool) TimeDataOption {
	return func(td *TimeData) {
		td.CreationTime.Formatted = formatted
		td.LastModificationTime.Formatted = formatted
		td.LastAccessTime.Formatted = formatted
		td.LocationChanged.Formatted = formatted
	}
}

// TimeData contains all metadata related to times for groups and entries
// e.g. the last modification time or the creation time
type TimeData struct {
	CreationTime         *w.TimeWrapper `xml:"CreationTime"`
	LastModificationTime *w.TimeWrapper `xml:"LastModificationTime"`
	LastAccessTime       *w.TimeWrapper `xml:"LastAccessTime"`
	ExpiryTime           *w.TimeWrapper `xml:"ExpiryTime"`
	Expires              w.BoolWrapper  `xml:"Expires"`
	UsageCount           int64          `xml:"UsageCount"`
	LocationChanged      *w.TimeWrapper `xml:"LocationChanged"`
}

// NewTimeData returns a TimeData struct with good defaults (no expire time, all times set to now)
func NewTimeData(options ...TimeDataOption) TimeData {
	now := w.Now()
	td := TimeData{
		CreationTime:         &now,
		LastModificationTime: &now,
		LastAccessTime:       &now,
		LocationChanged:      &now,
		Expires:              false,
		UsageCount:           0,
	}

	for _, option := range options {
		option(&td)
	}

	return td
}
