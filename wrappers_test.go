package gokeepasslib

import (
	"encoding/xml"
	"testing"
	"time"

	. "github.com/tobischo/gokeepasslib/v2/wrappers"
)

func TestTimeWrapperMarshalText(t *testing.T) {
	cases := []struct {
		title    string
		valueFn  func() time.Time
		expValue string
		expErr   error
	}{
		{
			title: "negative year",
			valueFn: func() time.Time {
				return time.Date(-1, time.June, 10, 6, 34, 12, 123123, time.UTC)
			},
			expErr: ErrYearOutsideOfRange,
		},
		{
			title: "year above 10000",
			valueFn: func() time.Time {
				return time.Date(10001, time.June, 10, 6, 34, 12, 123123, time.UTC)
			},
			expErr: ErrYearOutsideOfRange,
		},
		{
			title: "realistic year (2018)",
			valueFn: func() time.Time {
				ref, _ := time.Parse(time.RFC3339, "2018-06-10T06:20:23+02:00")
				return ref
			},
			expValue: "2018-06-10T04:20:23Z",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			value := c.valueFn()

			timeWrap := TimeWrapper{
				Formatted: true,
				Time:      value,
			}
			data, err := timeWrap.MarshalText()
			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}

			if string(data) != c.expValue {
				t.Errorf(
					"Did not marshal into expected string '%s', received: '%s'",
					c.expValue,
					string(data),
				)
			}
		})
	}
}

func TestTimeWrapperUnmarshalText(t *testing.T) {
	cases := []struct {
		title    string
		value    string
		expValue time.Time
		expErr   error
	}{
		{
			title:    "Non UTC RFC3339 compatible value",
			value:    "2018-06-10T06:20:23+02:00",
			expValue: time.Date(2018, time.June, 10, 4, 20, 23, 0, time.UTC),
		},
		{
			title:    "UTC RFC3339 compatible value",
			value:    "2018-06-10T04:20:23Z",
			expValue: time.Date(2018, time.June, 10, 4, 20, 23, 0, time.UTC),
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {

			timeWrap := &TimeWrapper{
				Formatted: true,
			}
			err := timeWrap.UnmarshalText([]byte(c.value))
			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}

			if !timeWrap.Time.Equal(c.expValue) {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, *timeWrap)
			}
		})
	}
}

func TestBoolWrapperUnmarshal(t *testing.T) {
	cases := []struct {
		title    string
		value    string
		expValue bool
		expErr   error
	}{
		{
			title:    "lowercase true",
			value:    `<Wrap><Val>true</Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase true",
			value:    `<Wrap><Val>TrUe</Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "lowercase false",
			value:    `<Wrap><Val>false</Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "mixedcase false",
			value:    `<Wrap><Val>FaLsE</Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "neither true nor false defaults to false",
			value:    `<Wrap><Val>neither</Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var x struct {
				Val BoolWrapper `xml:"Val"`
			}
			err := xml.Unmarshal([]byte(c.value), &x)

			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if bool(x.Val) != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val)
			}

		})
	}
}

func TestBoolWrapperUnmarshalAttr(t *testing.T) {
	cases := []struct {
		title    string
		value    string
		expValue bool
		expErr   error
	}{
		{
			title:    "lowercase true",
			value:    `<Wrap><Val v="true"></Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase true",
			value:    `<Wrap><Val v="TrUe"></Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "lowercase false",
			value:    `<Wrap><Val v="false"></Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "mixedcase false",
			value:    `<Wrap><Val v="FaLsE"></Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "neither true nor false defaults to false",
			value:    `<Wrap><Val v="neither"></Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var x struct {
				Val struct {
					Content string      `xml:",chardata"`
					V       BoolWrapper `xml:"v,attr,omitempty"`
				}
			}
			err := xml.Unmarshal([]byte(c.value), &x)

			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if bool(x.Val.V) != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.V)
			}

		})
	}
}
