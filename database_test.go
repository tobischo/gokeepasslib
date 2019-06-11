package gokeepasslib

import (
	"testing"
)

func TestNewDatabase(t *testing.T) {
	cases := []struct {
		title            string
		options          []DatabaseOption
		expectedDatabase *Database
	}{
		{
			title: "without options",
			expectedDatabase: &Database{
				Options: &DBOptions{
					ValidateHashes: true,
				},
			},
		},
		{
			title: "with multiple options",
			options: []DatabaseOption{
				WithDatabaseFormattedTime(false),
				func(c *Database) {
					c.Options.ValidateHashes = false
				},
			},
			expectedDatabase: &Database{
				Options: &DBOptions{
					ValidateHashes: false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			database := NewDatabase(c.options...)

			if database.Options.ValidateHashes != c.expectedDatabase.Options.ValidateHashes {
				t.Errorf(
					"Did not receive expected database %+v, received %+v",
					database.Options.ValidateHashes,
					c.expectedDatabase.Options.ValidateHashes,
				)
			}
		})
	}
}
