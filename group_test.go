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
