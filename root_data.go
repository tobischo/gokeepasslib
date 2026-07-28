package gokeepasslib

type RootDataOption func(*RootData)

func WithRootDataFormattedTime(formatted bool) RootDataOption {
	return func(rd *RootData) {
		for _, group := range rd.Groups {
			g := group

			WithGroupFormattedTime(formatted)(&g)
		}
	}
}

// RootData stores the actual content of a database
// (all enteries sorted into groups and the recycle bin)
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

// kdbx41Field returns the name of the first field within the group tree which
// can only be represented in KDBX 4.1 files, or an empty string if there is none
func (rd *RootData) kdbx41Field() string {
	for i := range rd.Groups {
		if field := (&rd.Groups[i]).kdbx41Field(); field != "" {
			return field
		}
	}

	return ""
}

func (rd *RootData) setKdbxFormatVersion(version formatVersion) {
	for i := range rd.Groups {
		(&rd.Groups[i]).setKdbxFormatVersion(version)
	}

	for i := range rd.DeletedObjects {
		(&rd.DeletedObjects[i]).setKdbxFormatVersion(version)
	}
}
