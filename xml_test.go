package gokeepasslib

import (
	"reflect"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v2/wrappers"
)

func TestUUID(t *testing.T) {
	one := UUID{}
	err := one.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plA=="))
	if err != nil {
		t.Fatalf("Error unmarshaling uuid: %s", err.Error())
	}
	mar, err := one.MarshalText()
	if err != nil {
		t.Fatalf("Error marshaling uuid")
	}
	if string(mar) != "rGnBe1gIikK89aZD6n/plA==" {
		t.Fatalf("UUID marshaled incorrectly. Expececting %s, got %s", "rGnBe1gIikK89aZD6n/plA==", mar)
	}

	two := one
	if !two.Compare(one) {
		t.Fatalf("One and Two UUIDs should be equal, are not")
	}

	three := UUID{}
	err = three.UnmarshalText([]byte("rGnBe1gIikK89aZD6n/plABBBB=="))
	if err != ErrInvalidUUIDLength {
		t.Fatalf("Expected invalid uuid error, got: %s", err)
	}
}

func TestNewRootData(t *testing.T) {
	cases := []struct {
		title            string
		options          []RootDataOption
		expectedRootData RootData
	}{
		{
			title: "without options",
			expectedRootData: RootData{
				Groups: []Group{
					Group{
						Name: "NewDatabase",
					},
				},
			},
		},
		{
			title: "with multiple options",
			options: []RootDataOption{
				WithRootDataFormattedTime(false),
				func(rd *RootData) {
					rd.Groups[0].Name = "other name"
				},
			},
			expectedRootData: RootData{
				Groups: []Group{
					Group{
						Name: "other name",
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			rootData := NewRootData(c.options...)

			if rootData.Groups[0].Name != c.expectedRootData.Groups[0].Name {
				t.Errorf(
					"Did not receive expected name %+v, received %+v",
					rootData.Groups[0].Name,
					c.expectedRootData.Groups[0].Name,
				)
			}
		})
	}
}

func TestNewMetaData(t *testing.T) {
	cases := []struct {
		title            string
		options          []MetaDataOption
		expectedMetaData *MetaData
	}{
		{
			title: "without options",
			expectedMetaData: &MetaData{
				MasterKeyChangeRec:     -1,
				MasterKeyChangeForce:   -1,
				HistoryMaxItems:        10,
				HistoryMaxSize:         6291456, // 6 MB
				MaintenanceHistoryDays: 365,
			},
		},
		{
			title: "with multiple options",
			options: []MetaDataOption{
				WithMetaDataFormattedTime(false),
				func(md *MetaData) {
					md.MaintenanceHistoryDays = 123
				},
			},
			expectedMetaData: &MetaData{
				MasterKeyChangeRec:     -1,
				MasterKeyChangeForce:   -1,
				HistoryMaxItems:        10,
				HistoryMaxSize:         6291456, // 6 MB
				MaintenanceHistoryDays: 123,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			metaData := NewMetaData(c.options...)

			c.expectedMetaData.MasterKeyChanged = metaData.MasterKeyChanged

			if !reflect.DeepEqual(metaData, c.expectedMetaData) {
				t.Errorf(
					"Did not receive expected MetaData %+v, received %+v",
					c.expectedMetaData,
					metaData,
				)
			}
		})
	}
}

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

func TestNewGroup(t *testing.T) {
	cases := []struct {
		title         string
		options       []GroupOption
		expectedGroup Group
	}{
		{
			title: "without options",
			expectedGroup: Group{
				Name: "",
			},
		},
		{
			title: "with multiple options",
			options: []GroupOption{
				WithGroupFormattedTime(false),
				func(rd *Group) {
					rd.Name = "other name"
				},
			},
			expectedGroup: Group{
				Name: "other name",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			group := NewGroup(c.options...)

			if group.Name != c.expectedGroup.Name {
				t.Errorf(
					"Did not receive expected name %+v, received %+v",
					group.Name,
					c.expectedGroup.Name,
				)
			}
		})
	}
}

func TestNewTimeData(t *testing.T) {
	cases := []struct {
		title            string
		options          []TimeDataOption
		expectedTimeData TimeData
	}{
		{
			title: "without options",
			expectedTimeData: TimeData{
				CreationTime: &wrappers.TimeWrapper{
					Formatted: true,
				},
				LastModificationTime: &wrappers.TimeWrapper{
					Formatted: true,
				},
				LastAccessTime: &wrappers.TimeWrapper{
					Formatted: true,
				},
				LocationChanged: &wrappers.TimeWrapper{
					Formatted: true,
				},
			},
		},
		{
			title: "with multiple options",
			options: []TimeDataOption{
				WithTimeDataFormattedTime(false),
				func(td *TimeData) {
					td.UsageCount = 10
				},
			},
			expectedTimeData: TimeData{
				CreationTime: &wrappers.TimeWrapper{
					Formatted: false,
				},
				LastModificationTime: &wrappers.TimeWrapper{
					Formatted: false,
				},
				LastAccessTime: &wrappers.TimeWrapper{
					Formatted: false,
				},
				LocationChanged: &wrappers.TimeWrapper{
					Formatted: false,
				},
				UsageCount: 10,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			timeData := NewTimeData(c.options...)

			if time.Since(timeData.CreationTime.Time) > time.Second {
				t.Error("CreationTime not properly initialized: should be time.Now()")
			}
			if time.Since(timeData.LastModificationTime.Time) > time.Second {
				t.Error("LastModificationTime not properly initialized: should be time.Now()")
			}
			if time.Since(timeData.LastAccessTime.Time) > time.Second {
				t.Error("LastAccessTime not properly initialized: should be time.Now()")
			}
			if timeData.ExpiryTime != nil {
				t.Error("ExpiryTime not properly initialized: should be nil")
			}
			if time.Since(timeData.LocationChanged.Time) > time.Second {
				t.Error("LocationChanged not properly initialized: should be time.Now()")
			}

			// times and uuids are generated at random.
			// testing them with a clear comparison does not work
			c.expectedTimeData.CreationTime.Time = timeData.CreationTime.Time
			c.expectedTimeData.LastModificationTime.Time = timeData.LastModificationTime.Time
			c.expectedTimeData.LastAccessTime.Time = timeData.LastAccessTime.Time
			c.expectedTimeData.LocationChanged.Time = timeData.LocationChanged.Time

			if !reflect.DeepEqual(timeData, c.expectedTimeData) {
				t.Errorf(
					"Did not receive expected timeData %+v, received %+v",
					c.expectedTimeData,
					timeData,
				)
			}

		})
	}
}
