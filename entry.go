package gokeepasslib

import (
	"encoding/xml"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

type EntryOption func(*Entry)

func WithEntryFormattedTime(formatted bool) EntryOption {
	return func(e *Entry) {
		WithTimeDataFormattedTime(formatted)(&e.Times)
	}
}

// Entry is the structure which holds information about a parsed entry in a keepass database
//
// The order of the fields matches the order in which KeePass writes the
// elements, as defined by the KDBX XML schema.
type Entry struct {
	UUID                UUID              `xml:"UUID"`
	IconID              int64             `xml:"IconID"`
	CustomIconUUID      UUID              `xml:"CustomIconUUID"`
	ForegroundColor     string            `xml:"ForegroundColor"`
	BackgroundColor     string            `xml:"BackgroundColor"`
	OverrideURL         string            `xml:"OverrideURL"`
	QualityCheck        *w.BoolWrapper    `xml:"QualityCheck,omitempty"` // KDBX 4.1
	Tags                string            `xml:"Tags"`
	PreviousParentGroup *UUID             `xml:"PreviousParentGroup,omitempty"` // KDBX 4.1
	Times               TimeData          `xml:"Times"`
	Values              []ValueData       `xml:"String,omitempty"`
	Binaries            []BinaryReference `xml:"Binary,omitempty"`
	AutoType            AutoTypeData      `xml:"AutoType"`
	CustomData          []CustomData      `xml:"CustomData>Item"`
	Histories           []History         `xml:"History"`
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

	setCustomDataKdbxFormatVersion(e.CustomData, version)

	for i := range e.Histories {
		(&e.Histories[i]).setKdbxFormatVersion(version)
	}
}

// kdbx41Field returns the name of the first field of the entry, or of one of
// its history entries, which can only be represented in KDBX 4.1 files.
// It returns an empty string if there is none.
func (e *Entry) kdbx41Field() string {
	if e.QualityCheck != nil {
		return "Entry.QualityCheck"
	}

	if e.PreviousParentGroup != nil {
		return "Entry.PreviousParentGroup"
	}

	if field := customDataKdbx41Field(e.CustomData); field != "" {
		return field
	}

	for i := range e.Histories {
		for j := range e.Histories[i].Entries {
			if field := (&e.Histories[i].Entries[j]).kdbx41Field(); field != "" {
				return field
			}
		}
	}

	return ""
}

// Clone creates a copy of an Entry struct including its child entities
func (e Entry) Clone() Entry {
	clone := e
	clone.UUID = NewUUID()
	if e.QualityCheck != nil {
		qualityCheck := *e.QualityCheck
		clone.QualityCheck = &qualityCheck
	}
	if e.PreviousParentGroup != nil {
		previousParentGroup := *e.PreviousParentGroup
		clone.PreviousParentGroup = &previousParentGroup
	}
	clone.Values = make([]ValueData, len(clone.Values))
	copy(clone.Values, e.Values)
	clone.Histories = make([]History, len(clone.Histories))
	for i, history := range e.Histories {
		clone.Histories[i] = history.Clone()
	}
	clone.Binaries = make([]BinaryReference, len(clone.Binaries))
	copy(clone.Binaries, e.Binaries)
	clone.CustomData = make([]CustomData, len(clone.CustomData))
	copy(clone.CustomData, e.CustomData)
	return clone
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

// Clone creates a copy of a History struct including its child entities
func (h History) Clone() History {
	clone := h

	clone.Entries = make([]Entry, len(h.Entries))
	for i, entry := range h.Entries {
		clone.Entries[i] = entry.Clone()
	}

	return clone
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
	Enabled                 w.BoolWrapper         `xml:"Enabled"`
	DataTransferObfuscation int64                 `xml:"DataTransferObfuscation"`
	DefaultSequence         string                `xml:"DefaultSequence"`
	Associations            []AutoTypeAssociation `xml:"Association,omitempty"`
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

	// LastModificationTime was added in KDBX 4.1.
	//
	// Note that the KDBX XML schema only documents it for the custom data of
	// the MetaData, while KeePass itself writes it for the custom data of
	// groups and entries as well. It is therefore supported in all three
	// places, matching the behaviour of KeePass.
	LastModificationTime *w.TimeWrapper `xml:"LastModificationTime,omitempty"`
}

func (cd *CustomData) setKdbxFormatVersion(version formatVersion) {
	if cd.LastModificationTime != nil {
		cd.LastModificationTime.Formatted = !isKdbx4(version)
	}
}

func setCustomDataKdbxFormatVersion(customData []CustomData, version formatVersion) {
	for i := range customData {
		(&customData[i]).setKdbxFormatVersion(version)
	}
}

// kdbx41Field returns the name of the first field which can only be
// represented in KDBX 4.1 files, or an empty string if there is none
func customDataKdbx41Field(customData []CustomData) string {
	for i := range customData {
		if customData[i].LastModificationTime != nil {
			return "CustomData.LastModificationTime"
		}
	}

	return ""
}
