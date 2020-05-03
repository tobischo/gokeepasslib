package gokeepasslib

import (
	"testing"
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
