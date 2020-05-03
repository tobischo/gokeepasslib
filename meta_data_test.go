package gokeepasslib

import (
	"reflect"
	"testing"
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
