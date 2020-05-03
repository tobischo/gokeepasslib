package gokeepasslib

import (
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

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
	UUID                    UUID                  `xml:"UUID"`
	Name                    string                `xml:"Name"`
	Notes                   string                `xml:"Notes"`
	IconID                  int64                 `xml:"IconID"`
	Times                   TimeData              `xml:"Times"`
	IsExpanded              w.BoolWrapper         `xml:"IsExpanded"`
	DefaultAutoTypeSequence string                `xml:"DefaultAutoTypeSequence"`
	EnableAutoType          w.NullableBoolWrapper `xml:"EnableAutoType"`
	EnableSearching         w.NullableBoolWrapper `xml:"EnableSearching"`
	LastTopVisibleEntry     string                `xml:"LastTopVisibleEntry"`
	Entries                 []Entry               `xml:"Entry,omitempty"`
	Groups                  []Group               `xml:"Group,omitempty"`
}

// NewGroup returns a new group with time data and uuid set
func NewGroup(options ...GroupOption) Group {
	group := Group{
		EnableAutoType:  w.NewNullableBoolWrapper(true),
		EnableSearching: w.NewNullableBoolWrapper(true),
		Times:           NewTimeData(),
		UUID:            NewUUID(),
	}

	for _, option := range options {
		option(&group)
	}

	return group
}

func (g *Group) setKdbxFormatVersion(version formatVersion) {
	(&g.Times).setKdbxFormatVersion(version)

	for i := range g.Groups {
		(&g.Groups[i]).setKdbxFormatVersion(version)
	}

	for i := range g.Entries {
		(&g.Entries[i]).setKdbxFormatVersion(version)
	}
}
