package gokeepasslib

import (
	"reflect"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

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

func TestMetaDataSetKdbxFormatVersion(t *testing.T) {
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
			md := &MetaData{
				DatabaseNameChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
				DatabaseDescriptionChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
				DefaultUserNameChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
				MasterKeyChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
				RecycleBinChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
				EntryTemplatesGroupChanged: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
			}

			md.setKdbxFormatVersion(c.version)

			if md.DatabaseNameChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set DatabaseNameChanged formatted value accordingly")
			}
			if md.DatabaseDescriptionChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set DatabaseDescriptionChanged formatted value accordingly")
			}
			if md.DefaultUserNameChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set DefaultUserNameChanged formatted value accordingly")
			}
			if md.MasterKeyChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set MasterKeyChanged formatted value accordingly")
			}
			if md.RecycleBinChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set RecycleBinChanged formatted value accordingly")
			}
			if md.EntryTemplatesGroupChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set EntryTemplatesGroupChanged formatted value accordingly")
			}
		})
	}
}
