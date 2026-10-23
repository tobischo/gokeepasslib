package gokeepasslib

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"

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

	// childOrder is the order of the values and histories in the XML document.
	// The inner random stream has to be consumed in this order when unlocking
	childOrder []xmlChild `xml:"-"`
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

// UnmarshalXML unmarshals the entry from d
func (e *Entry) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	for {
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			// Propagating child errors is essential: silently dropping an
			// unparseable child desyncs the protection stream cipher and
			// corrupts every protected value that follows it.
			if err := unmarshalEntryToken(e, d, element); err != nil {
				return fmt.Errorf("failed to unmarshal entry child %q: %w", element.Name.Local, err)
			}
		}
	}

	return nil
}

func unmarshalEntryToken(e *Entry, d *xml.Decoder, element xml.StartElement) error {
	switch element.Name.Local {
	case "String":
		var value ValueData
		if err := d.DecodeElement(&value, &element); err != nil {
			return err
		}

		e.Values = append(e.Values, value)
		e.childOrder = append(e.childOrder, xmlChildValue)
	case "History":
		var history History
		if err := d.DecodeElement(&history, &element); err != nil {
			return err
		}

		e.Histories = append(e.Histories, history)
		e.childOrder = append(e.childOrder, xmlChildHistory)
	case uuidElement:
		return d.DecodeElement(&e.UUID, &element)
	case "IconID":
		return d.DecodeElement(&e.IconID, &element)
	case customIconUUIDElement:
		return d.DecodeElement(&e.CustomIconUUID, &element)
	case "ForegroundColor":
		return d.DecodeElement(&e.ForegroundColor, &element)
	case "BackgroundColor":
		return d.DecodeElement(&e.BackgroundColor, &element)
	case "OverrideURL":
		return d.DecodeElement(&e.OverrideURL, &element)
	case "QualityCheck":
		e.QualityCheck = new(w.BoolWrapper)
		return d.DecodeElement(e.QualityCheck, &element)
	case "Tags":
		return d.DecodeElement(&e.Tags, &element)
	case "PreviousParentGroup":
		e.PreviousParentGroup = new(UUID)
		return d.DecodeElement(e.PreviousParentGroup, &element)
	case "Times":
		return d.DecodeElement(&e.Times, &element)
	case "Binary":
		var binary BinaryReference
		if err := d.DecodeElement(&binary, &element); err != nil {
			return err
		}

		e.Binaries = append(e.Binaries, binary)
	case "AutoType":
		return d.DecodeElement(&e.AutoType, &element)
	case "CustomData":
		var customData struct {
			Items []CustomData `xml:"Item"`
		}
		if err := d.DecodeElement(&customData, &element); err != nil {
			return err
		}

		e.CustomData = append(e.CustomData, customData.Items...)
	default:
		// Unknown elements are ignored, as they were by the default decoding
		return d.Skip()
	}

	return nil
}

// kdbx41Field returns the name of the first field of the entry, or of one of
// its history entries, which can only be represented in KDBX 4.1 files.
// It returns an empty string if there is none.
func (e *Entry) kdbx41Field() string {
	if e.QualityCheck != nil {
		return fieldEntryQualityCheck
	}

	if e.PreviousParentGroup != nil {
		return fieldEntryPreviousParentGroup
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
			return fieldCustomDataLastModificationTime
		}
	}

	return ""
}
