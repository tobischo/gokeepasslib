package gokeepasslib

import (
	"encoding/xml"
	"errors"
	"io"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

const (
	groupChildOrderDefault = iota
	groupChildOrderEntryFirst
	groupChildOrderGroupFirst
)

type GroupOption func(*Group)

func WithGroupFormattedTime(formatted bool) GroupOption {
	return func(g *Group) {
		WithTimeDataFormattedTime(formatted)(&g.Times)

		for _, group := range g.Groups {
			g := group

			WithGroupFormattedTime(formatted)(&g)
		}

		for _, entry := range g.Entries {
			e := entry

			WithEntryFormattedTime(formatted)(&e)
		}
	}
}

// Group is a structure to store entries in their named groups for organization
//
// The order of the fields matches the order in which KeePass writes the
// elements, as defined by the KDBX XML schema.
type Group struct {
	UUID                    UUID                  `xml:"UUID"`
	Name                    string                `xml:"Name"`
	Notes                   string                `xml:"Notes"`
	IconID                  int64                 `xml:"IconID"`
	CustomIconUUID          UUID                  `xml:"CustomIconUUID"`
	Times                   TimeData              `xml:"Times"`
	IsExpanded              w.BoolWrapper         `xml:"IsExpanded"`
	DefaultAutoTypeSequence string                `xml:"DefaultAutoTypeSequence"`
	EnableAutoType          w.NullableBoolWrapper `xml:"EnableAutoType"`
	EnableSearching         w.NullableBoolWrapper `xml:"EnableSearching"`
	LastTopVisibleEntry     string                `xml:"LastTopVisibleEntry"`
	PreviousParentGroup     *UUID                 `xml:"PreviousParentGroup,omitempty"` // KDBX 4.1
	Tags                    string                `xml:"Tags,omitempty"`                // KDBX 4.1
	CustomData              []CustomData          `xml:"CustomData>Item"`               // KDBX 4
	Entries                 []Entry               `xml:"Entry,omitempty"`
	Groups                  []Group               `xml:"Group,omitempty"`
	groupChildOrder         int                   `xml:"-"`
}

// kdbx41Field returns the name of the first field of the group, or of one of its
// child groups and entries, which can only be represented in KDBX 4.1 files.
// It returns an empty string if there is none.
func (g *Group) kdbx41Field() string {
	if g.PreviousParentGroup != nil {
		return "Group.PreviousParentGroup"
	}

	if g.Tags != "" {
		return "Group.Tags"
	}

	if field := customDataKdbx41Field(g.CustomData); field != "" {
		return field
	}

	for i := range g.Entries {
		if field := (&g.Entries[i]).kdbx41Field(); field != "" {
			return field
		}
	}

	for i := range g.Groups {
		if field := (&g.Groups[i]).kdbx41Field(); field != "" {
			return field
		}
	}

	return ""
}

// Clone creates a copy of a Group struct including its child entities
func (g Group) Clone() Group {
	clone := g
	clone.UUID = NewUUID()
	if g.PreviousParentGroup != nil {
		previousParentGroup := *g.PreviousParentGroup
		clone.PreviousParentGroup = &previousParentGroup
	}
	if g.CustomData != nil {
		clone.CustomData = make([]CustomData, len(g.CustomData))
		copy(clone.CustomData, g.CustomData)
	}
	clone.Entries = make([]Entry, len(clone.Entries))
	for i, entry := range g.Entries {
		clone.Entries[i] = entry.Clone()
	}
	clone.Groups = make([]Group, len(clone.Groups))
	for i, group := range g.Groups {
		clone.Groups[i] = group.Clone()
	}
	return clone
}

// UnmarshalXML unmarshals the boolean from d
func (g *Group) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			unmarshalGroupToken(g, d, element)
		}
	}

	return nil
}

func unmarshalGroupToken(g *Group, d *xml.Decoder, element xml.StartElement) error {
	switch element.Name.Local {
	case "Entry":
		if g.groupChildOrder == groupChildOrderDefault {
			g.groupChildOrder = groupChildOrderEntryFirst
		}

		var entry Entry
		err := d.DecodeElement(&entry, &element)
		if err != nil {
			return err
		}

		g.Entries = append(g.Entries, entry)
	case "Group":
		if g.groupChildOrder == groupChildOrderDefault {
			g.groupChildOrder = groupChildOrderGroupFirst
		}

		var group Group
		err := d.DecodeElement(&group, &element)
		if err != nil {
			return err
		}

		g.Groups = append(g.Groups, group)
	case uuidElement:
		return d.DecodeElement(&g.UUID, &element)
	case "Name":
		return d.DecodeElement(&g.Name, &element)
	case "Notes":
		return d.DecodeElement(&g.Notes, &element)
	case "IconID":
		return d.DecodeElement(&g.IconID, &element)
	case customIconUUIDElement:
		return d.DecodeElement(&g.CustomIconUUID, &element)
	case "Times":
		return d.DecodeElement(&g.Times, &element)
	case "IsExpanded":
		return d.DecodeElement(&g.IsExpanded, &element)
	case "DefaultAutoTypeSequence":
		return d.DecodeElement(&g.DefaultAutoTypeSequence, &element)
	case "EnableAutoType":
		return d.DecodeElement(&g.EnableAutoType, &element)
	case "EnableSearching":
		return d.DecodeElement(&g.EnableSearching, &element)
	case "LastTopVisibleEntry":
		return d.DecodeElement(&g.LastTopVisibleEntry, &element)
	case "PreviousParentGroup":
		g.PreviousParentGroup = new(UUID)
		return d.DecodeElement(g.PreviousParentGroup, &element)
	case "Tags":
		return d.DecodeElement(&g.Tags, &element)
	case "CustomData":
		var customData struct {
			Items []CustomData `xml:"Item"`
		}
		if err := d.DecodeElement(&customData, &element); err != nil {
			return err
		}

		g.CustomData = customData.Items
	}

	return nil
}

// NewGroup returns a new group with time data and uuid set
func NewGroup(options ...GroupOption) Group {
	group := Group{
		EnableAutoType:      w.NewNullableBoolWrapper(true),
		EnableSearching:     w.NewNullableBoolWrapper(true),
		Times:               NewTimeData(),
		UUID:                NewUUID(),
		LastTopVisibleEntry: ZeroUUIDText, // value required by KDBX XML schema. Init as zero UUID.
	}

	for _, option := range options {
		option(&group)
	}

	return group
}

func (g *Group) setKdbxFormatVersion(version formatVersion) {
	(&g.Times).setKdbxFormatVersion(version)

	setCustomDataKdbxFormatVersion(g.CustomData, version)

	for i := range g.Groups {
		(&g.Groups[i]).setKdbxFormatVersion(version)
	}

	for i := range g.Entries {
		(&g.Entries[i]).setKdbxFormatVersion(version)
	}
}
