package gokeepasslib

import (
	"testing"
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
