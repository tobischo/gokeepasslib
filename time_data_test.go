package gokeepasslib

import (
	"reflect"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

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
				Expires: wrappers.BoolWrapper{
					Bool: false,
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
				Expires: wrappers.BoolWrapper{
					Bool: false,
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

func TestTimeDataSetKdbxFormatVersion(t *testing.T) {
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
			td := NewTimeData(
				WithTimeDataFormattedTime(c.formattedInitValue),
			)

			(&td).setKdbxFormatVersion(c.version)

			if td.CreationTime != nil &&
				td.CreationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set CreationTime formatted value accordingly")
			}
			if td.LastModificationTime != nil &&
				td.LastModificationTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set LastModificationTime formatted value accordingly")
			}
			if td.LastAccessTime != nil &&
				td.LastAccessTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set LastAccessTime formatted value accordingly")
			}
			if td.ExpiryTime != nil &&
				td.ExpiryTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set ExpiryTime formatted value accordingly")
			}
			if td.LocationChanged != nil &&
				td.LocationChanged.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set LocationChanged formatted value accordingly")
			}
		})
	}
}
