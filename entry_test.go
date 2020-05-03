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
