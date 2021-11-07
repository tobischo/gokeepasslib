package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"errors"
	"reflect"
	"testing"
	"time"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

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
		{
			title: "with custom icon",
			options: []GroupOption{
				WithGroupFormattedTime(false),
				func(rd *Group) {
					rd.CustomIconUUID = UUID{0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xde, 0xed, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
				},
			},
			expectedGroup: Group{
				CustomIconUUID: UUID{0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xde, 0xed, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd},
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

func TestGroupSetKdbxFormatVersion(t *testing.T) {
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
			group := NewGroup(
				WithGroupFormattedTime(c.formattedInitValue),
			)

			entry := NewEntry(
				WithEntryFormattedTime(c.formattedInitValue),
			)
			group.Entries = append(group.Entries, entry)

			subGroup := NewGroup(
				WithGroupFormattedTime(c.formattedInitValue),
			)
			group.Groups = append(group.Groups, subGroup)

			(&group).setKdbxFormatVersion(c.version)

			// Takes a single time value as an example, as TimeData is independently tested.
			if group.Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set root CreationTime formatted value accordingly")
			}

			if group.Groups[0].Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set sub group CreationTime formatted value accordingly")
			}

			if group.Entries[0].Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set entry CreationTime formatted value accordingly")
			}
		})
	}
}

func TestGroupUnmarshalXML(t *testing.T) {
	creationTime, _ := time.Parse(time.RFC3339, "2019-04-19T13:09:26+02:00")
	lastModificationTime, _ := time.Parse(time.RFC3339, "2019-04-19T13:09:26+02:00")
	lastAccessTime, _ := time.Parse(time.RFC3339, "2019-04-19T13:10:00+02:00")
	expiryTime, _ := time.Parse(time.RFC3339, "2019-04-19T13:07:11+02:00")
	locationChanged, _ := time.Parse(time.RFC3339, "2019-04-19T13:09:26+02:00")

	cases := []struct {
		title         string
		xmlData       string
		expectedGroup Group
		expectedErr   error
	}{
		{
			title:   "empty group",
			xmlData: "<Group></Group>",
		},
		{
			title:   "child group first",
			xmlData: "<Group><Group></Group><Entry></Entry></Group>",
			expectedGroup: Group{
				Entries:         []Entry{{}},
				Groups:          []Group{{}},
				groupChildOrder: groupChildOrderGroupFirst,
			},
		},
		{
			title:   "child entry first",
			xmlData: "<Group><Entry></Entry><Group></Group></Group>",
			expectedGroup: Group{
				Entries:         []Entry{{}},
				Groups:          []Group{{}},
				groupChildOrder: groupChildOrderEntryFirst,
			},
		},
		{
			title: "with the other fields",
			xmlData: `
      <Group>
        <UUID>uJSFMJ8KrUSO0Qiivnk2Eg==</UUID>
        <Name>kdbx4key</Name>
        <Notes>notes</Notes>
        <IconID>49</IconID>
        <Times>
          <CreationTime>ZqNL1A4AAAA=</CreationTime>
          <LastModificationTime>ZqNL1A4AAAA=</LastModificationTime>
          <LastAccessTime>iKNL1A4AAAA=</LastAccessTime>
          <ExpiryTime>36JL1A4AAAA=</ExpiryTime>
          <Expires>False</Expires>
          <UsageCount>1</UsageCount>
          <LocationChanged>ZqNL1A4AAAA=</LocationChanged>
        </Times>
        <IsExpanded>True</IsExpanded>
        <DefaultAutoTypeSequence>abc</DefaultAutoTypeSequence>
        <EnableAutoType>True</EnableAutoType>
        <EnableSearching>False</EnableSearching>
        <LastTopVisibleEntry>SnB29sd3a06jo6GR1BkGBQ==</LastTopVisibleEntry>
       </Group>`,
			expectedGroup: Group{
				UUID: UUID{
					0xb8, 0x94, 0x85, 0x30,
					0x9f, 0xa, 0xad, 0x44,
					0x8e, 0xd1, 0x8, 0xa2,
					0xbe, 0x79, 0x36, 0x12,
				},
				Name:   "kdbx4key",
				Notes:  "notes",
				IconID: 49,
				Times: TimeData{
					CreationTime:         &w.TimeWrapper{Formatted: false, Time: creationTime},
					LastModificationTime: &w.TimeWrapper{Formatted: false, Time: lastModificationTime},
					LastAccessTime:       &w.TimeWrapper{Formatted: false, Time: lastAccessTime},
					ExpiryTime:           &w.TimeWrapper{Formatted: false, Time: expiryTime},
					Expires:              w.NewBoolWrapper(false),
					UsageCount:           1,
					LocationChanged:      &w.TimeWrapper{Formatted: false, Time: locationChanged},
				},
				IsExpanded:              w.NewBoolWrapper(true),
				DefaultAutoTypeSequence: "abc",
				EnableAutoType:          w.NewNullableBoolWrapper(true),
				EnableSearching:         w.NewNullableBoolWrapper(false),
				LastTopVisibleEntry:     "SnB29sd3a06jo6GR1BkGBQ==",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			decoder := xml.NewDecoder(bytes.NewBuffer([]byte(c.xmlData)))

			var group Group

			err := decoder.Decode(&group)

			if !errors.Is(c.expectedErr, err) {
				t.Errorf("Expected %#v, received %#v", c.expectedErr, err)
			}

			if !reflect.DeepEqual(c.expectedGroup, group) {
				t.Errorf("Expected %#v, received %#v", c.expectedGroup, group)
			}

		})
	}
}
