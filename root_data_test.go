package gokeepasslib

import (
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

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

func TestRootDataSetKdbxFormatVersion(t *testing.T) {
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
			rootData := NewRootData(
				WithRootDataFormattedTime(c.formattedInitValue),
			)
			rootData.DeletedObjects = append(
				rootData.DeletedObjects,
				DeletedObjectData{
					DeletionTime: &wrappers.TimeWrapper{
						Time:      time.Now(),
						Formatted: c.formattedInitValue,
					},
				},
			)

			rootData.setKdbxFormatVersion(c.version)

			// Takes a single time value as an example, as TimeData is independently tested.
			if rootData.Groups[0].Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set group CreationTime formatted value accordingly")
			}

			if rootData.Groups[0].Entries[0].Times.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set entry CreationTime formatted value accordingly")
			}

			if rootData.DeletedObjects[0].DeletionTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set deleted object DeletionTime formatted value accordingly")
			}
		})
	}

}
