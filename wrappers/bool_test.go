package wrappers

import (
	"encoding/xml"
	"testing"
)

func TestBoolWrapperUnmarshalXML(t *testing.T) {
	cases := []struct {
		title    string
		value    string
		expValue bool
		expValid bool
		expErr   error
	}{
		{
			title:    "lowercase true",
			value:    `<Wrap><Val>true</Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase true",
			value:    `<Wrap><Val>TrUe</Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "lowercase false",
			value:    `<Wrap><Val>false</Val></Wrap>`,
			expValue: false,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase false",
			value:    `<Wrap><Val>FaLsE</Val></Wrap>`,
			expValue: false,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "null value",
			value:    `<Wrap><Val>null</Val></Wrap>`,
			expValue: false,
			expValid: false,
			expErr:   nil,
		},
		{
			title:    "not set at all",
			value:    `<Wrap></Wrap>`,
			expValue: false,
			expValid: false,
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
			if bool(x.Val.Bool) != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.Bool)
			}
			if bool(x.Val.Valid) != c.expValid {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValid, x.Val.Valid)
			}

		})
	}
}

func TestBoolWrapperUnmarshalXMLAttr(t *testing.T) {
	cases := []struct {
		title    string
		value    string
		expValue bool
		expValid bool
		expErr   error
	}{
		{
			title:    "lowercase true",
			value:    `<Wrap><Val v="true"></Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase true",
			value:    `<Wrap><Val v="TrUe"></Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "lowercase false",
			value:    `<Wrap><Val v="false"></Val></Wrap>`,
			expValue: false,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "mixedcase false",
			value:    `<Wrap><Val v="FaLsE"></Val></Wrap>`,
			expValue: false,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "null value",
			value:    `<Wrap><Val v="null"></Val></Wrap>`,
			expValue: false,
			expValid: false,
			expErr:   nil,
		},
		{
			title:    "when it is not set at all",
			value:    `<Wrap><Val ></Val></Wrap>`,
			expValue: false,
			expValid: false,
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
			if bool(x.Val.V.Bool) != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.V.Bool)
			}

			if bool(x.Val.V.Valid) != c.expValid {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValid, x.Val.V.Valid)
			}

		})
	}
}
