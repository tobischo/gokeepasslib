package gokeepasslib

import (
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestDeletedObjectDataSetKdbxFormatVersion(t *testing.T) {
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
			d := &DeletedObjectData{
				DeletionTime: &wrappers.TimeWrapper{
					Time:      time.Now(),
					Formatted: c.formattedInitValue,
				},
			}

			d.setKdbxFormatVersion(c.version)

			if d.DeletionTime != nil &&
				d.DeletionTime.Formatted != c.expectedFormattedValue {

				t.Errorf("Failed to set DeletionTime formatted value accordingly")
			}
		})
	}
}
