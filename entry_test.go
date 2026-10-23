package gokeepasslib

import (
	"encoding/xml"
	"reflect"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestNewEntry(t *testing.T) {
	cases := []struct {
		title         string
		options       []EntryOption
		expectedEntry Entry
	}{
		{
			title:         "without options",
			expectedEntry: Entry{},
		},
		{
			title: "with multiple options",
			options: []EntryOption{
				WithEntryFormattedTime(false),
				func(e *Entry) {
					e.Tags = "Test Tags"
				},
			},
			expectedEntry: Entry{
				Tags: "Test Tags",
			},
		},
		{
			title: "with custom icon",
			options: []EntryOption{
				WithEntryFormattedTime(false),
				func(e *Entry) {
					e.CustomIconUUID = UUID{
						0xde, 0xad, 0xbe, 0xef,
						0xc0, 0xff, 0xee, 0xde,
						0xed, 0x01, 0x23, 0x45,
						0x67, 0x89, 0xab, 0xcd,
					}
				},
			},
			expectedEntry: Entry{
				CustomIconUUID: UUID{
					0xde, 0xad, 0xbe, 0xef,
					0xc0, 0xff, 0xee, 0xde,
					0xed, 0x01, 0x23, 0x45,
					0x67, 0x89, 0xab, 0xcd,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			entry := NewEntry(c.options...)

			// times and uuids are generated at random.
			// testing them with a clear comparison does not work
			c.expectedEntry.Times = entry.Times
			c.expectedEntry.UUID = entry.UUID

			if !reflect.DeepEqual(entry, c.expectedEntry) {
				t.Errorf(
					"Did not receive expected Entry %+v, received %+v",
					c.expectedEntry,
					entry,
				)
			}
		})
	}
}

func compareEntry(a, b Entry) bool {
	if !cmp.Equal(
		a,
		b,
		cmp.AllowUnexported(Entry{}),
		cmpopts.IgnoreFields(Entry{}, "Values", "Histories", "Binaries", "CustomData"),
	) {
		return false
	}

	if !slices.EqualFunc(
		a.Values,
		b.Values,
		func(a, b ValueData) bool {
			return cmp.Equal(a, b)
		},
	) {
		return false
	}

	if !slices.EqualFunc(
		a.Histories,
		b.Histories,
		func(a, b History) bool {
			return cmp.Equal(a, b, cmp.AllowUnexported(Entry{}))
		},
	) {
		return false
	}

	if !slices.EqualFunc(
		a.Binaries,
		b.Binaries,
		func(a, b BinaryReference) bool {
			return cmp.Equal(a, b)
		},
	) {
		return false
	}

	if !slices.EqualFunc(
		a.CustomData,
		b.CustomData,
		func(a, b CustomData) bool {
			return cmp.Equal(a, b)
		},
	) {
		return false
	}

	return true
}

func TestEntry_Clone(t *testing.T) {
	cases := []struct {
		title string
	}{
		{
			title: "success",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			entry := NewEntry()

			clone := entry.Clone()

			if &clone == &entry {
				t.Errorf("clone struct has the same pointer address")
			}

			if clone.UUID == entry.UUID {
				t.Errorf("clone did not receive a new UUID")
			}

			clone.UUID = entry.UUID
			if !compareEntry(entry, clone) {
				t.Errorf(
					"Did not receive expected Entry %+v, received %+v",
					clone,
					entry,
				)
			}
		})
	}
}

func TestEntrySetKdbxFormatVersion(t *testing.T) {
	cases := []struct {
		title                  string
		formattedInitValue     bool
		version                formatVersion
		expectedFormattedValue bool
	}{
		{
			title:                  "initialized as v3, changed to v4",
			formattedInitValue:     true,
			version:                formatVersion40,
			expectedFormattedValue: false,
		},
		{
			title:                  "initialized as v4, changed to v3",
			formattedInitValue:     false,
			version:                formatVersion31,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v3, not changed",
			formattedInitValue:     true,
			version:                formatVersion31,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v4, not changed",
			formattedInitValue:     false,
			version:                formatVersion40,
			expectedFormattedValue: false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			entry := NewEntry(
				WithEntryFormattedTime(c.formattedInitValue),
			)

			history := History{
				Entries: []Entry{
					NewEntry(
						WithEntryFormattedTime(c.formattedInitValue),
					),
				},
			}

			entry.Histories = append(entry.Histories, history)

			(&entry).setKdbxFormatVersion(c.version)

			// Takes a single time value as an example, as TimeData is independently tested.
			if entry.Times.CreationTime.Formatted != c.expectedFormattedValue {
				t.Errorf("Failed to set root CreationTime formatted value accordingly")
			}

			if entry.Histories[0].Entries[0].Times.CreationTime.Formatted != c.expectedFormattedValue {
				t.Errorf("Failed to set history CreationTime formatted value accordingly")
			}
		})
	}
}

func TestHistory_Clone(t *testing.T) {
	cases := []struct {
		title string
	}{
		{
			title: "success",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			entry := NewEntry()
			history := History{
				Entries: []Entry{entry},
			}

			clone := history.Clone()

			if &clone == &history {
				t.Errorf("clone struct has the same pointer address")
			}

			if clone.Entries[0].UUID == history.Entries[0].UUID {
				t.Errorf("cloned entry did not receive a new UUID")
			}

			clone.Entries[0].UUID = history.Entries[0].UUID
			if !slices.EqualFunc(
				history.Entries,
				clone.Entries,
				compareEntry,
			) {
				t.Errorf(
					"Did not receive expected History %+v, received %+v",
					clone,
					history,
				)
			}
		})
	}
}

func TestEntryUnmarshalXML(t *testing.T) {
	cases := []struct {
		title         string
		xmlData       string
		expectedEntry Entry
	}{
		{
			title:   "empty entry",
			xmlData: "<Entry></Entry>",
		},
		{
			title: "values and histories interleaved",
			xmlData: "<Entry>" +
				"<String><Key>Title</Key><Value>title</Value></String>" +
				"<History><Entry></Entry></History>" +
				"<String><Key>Password</Key><Value Protected=\"True\">password</Value></String>" +
				"</Entry>",
			expectedEntry: Entry{
				Values: []ValueData{
					{Key: "Title", Value: V{Content: "title"}},
					{Key: "Password", Value: V{Content: "password", Protected: w.NewBoolWrapper(true)}},
				},
				Histories:  []History{{Entries: []Entry{{}}}},
				childOrder: []xmlChild{xmlChildValue, xmlChildHistory, xmlChildValue},
			},
		},
		{
			title: "with the other fields",
			xmlData: "<Entry>" +
				"<UUID>uJSFMJ8KrUSO0Qiivnk2Eg==</UUID>" +
				"<IconID>49</IconID>" +
				"<ForegroundColor>#FF0000</ForegroundColor>" +
				"<BackgroundColor>#00FF00</BackgroundColor>" +
				"<OverrideURL>cmd://url</OverrideURL>" +
				"<QualityCheck>False</QualityCheck>" +
				"<Tags>tag1;tag2</Tags>" +
				"<PreviousParentGroup>SnB29sd3a06jo6GR1BkGBQ==</PreviousParentGroup>" +
				"<Binary><Key>file</Key><Value Ref=\"1\"/></Binary>" +
				"<AutoType><Enabled>True</Enabled>" +
				"<DefaultSequence>{PASSWORD}</DefaultSequence></AutoType>" +
				"<CustomData><Item><Key>key</Key><Value>value</Value></Item></CustomData>" +
				"<Unknown><String><Key>Ignored</Key></String></Unknown>" +
				"</Entry>",
			expectedEntry: Entry{
				UUID: UUID{
					0xb8, 0x94, 0x85, 0x30,
					0x9f, 0xa, 0xad, 0x44,
					0x8e, 0xd1, 0x8, 0xa2,
					0xbe, 0x79, 0x36, 0x12,
				},
				IconID:          49,
				ForegroundColor: "#FF0000",
				BackgroundColor: "#00FF00",
				OverrideURL:     "cmd://url",
				QualityCheck:    &w.BoolWrapper{Bool: false},
				Tags:            "tag1;tag2",
				PreviousParentGroup: &UUID{
					0x4a, 0x70, 0x76, 0xf6,
					0xc7, 0x77, 0x6b, 0x4e,
					0xa3, 0xa3, 0xa1, 0x91,
					0xd4, 0x19, 0x06, 0x05,
				},
				Binaries: []BinaryReference{{Name: "file", Value: struct {
					ID int `xml:"Ref,attr"`
				}{ID: 1}}},
				AutoType: AutoTypeData{
					Enabled:         w.NewBoolWrapper(true),
					DefaultSequence: "{PASSWORD}",
				},
				CustomData: []CustomData{{
					XMLName: xml.Name{Local: "Item"},
					Key:     "key",
					Value:   "value",
				}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var entry Entry
			if err := xml.Unmarshal([]byte(c.xmlData), &entry); err != nil {
				t.Fatalf("Failed to unmarshal entry: %v", err)
			}

			if !reflect.DeepEqual(entry, c.expectedEntry) {
				t.Fatalf("Received entry %+v, expected %+v", entry, c.expectedEntry)
			}
		})
	}
}
