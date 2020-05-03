package gokeepasslib

import (
	"reflect"
	"testing"
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
			version:                4,
			expectedFormattedValue: false,
		},
		{
			title:                  "initialized as v4, changed to v3",
			formattedInitValue:     false,
			version:                3,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v3, not changed",
			formattedInitValue:     true,
			version:                3,
			expectedFormattedValue: true,
		},
		{
			title:                  "initialized as v4, not changed",
			formattedInitValue:     false,
			version:                4,
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
