package wrappers

import (
	"encoding/xml"
	"errors"
	"testing"
)

func TestBoolWrapperUnmarshalXML(t *testing.T) {
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
			title:    "value is '1'",
			value:    `<Wrap><Val>1</Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'enabled'",
			value:    `<Wrap><Val>enabled</Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'checked'",
			value:    `<Wrap><Val>checked</Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'yes'",
			value:    `<Wrap><Val>yes</Val></Wrap>`,
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
			title:    "null value",
			value:    `<Wrap><Val>null</Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "not set at all",
			value:    `<Wrap></Wrap>`,
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

			if !errors.Is(err, c.expErr) {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if x.Val.Bool != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.Bool)
			}
		})
	}
}

func TestBoolWrapperUnmarshalXMLAttr(t *testing.T) {
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
			title:    "value is '1'",
			value:    `<Wrap><Val v="1"></Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'enabled'",
			value:    `<Wrap><Val v="enabled"></Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'checked'",
			value:    `<Wrap><Val v="checked"></Val></Wrap>`,
			expValue: true,
			expErr:   nil,
		},
		{
			title:    "value is 'yes'",
			value:    `<Wrap><Val v="yes"></Val></Wrap>`,
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
			title:    "null value",
			value:    `<Wrap><Val v="null"></Val></Wrap>`,
			expValue: false,
			expErr:   nil,
		},
		{
			title:    "when it is not set at all",
			value:    `<Wrap><Val ></Val></Wrap>`,
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

			if !errors.Is(err, c.expErr) {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if x.Val.V.Bool != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.V.Bool)
			}
		})
	}
}

func TestNullableBoolWrapperUnmarshalXML(t *testing.T) {
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
			title:    "value is '1'",
			value:    `<Wrap><Val>1</Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'enabled'",
			value:    `<Wrap><Val>enabled</Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'checked'",
			value:    `<Wrap><Val>checked</Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'yes'",
			value:    `<Wrap><Val>yes</Val></Wrap>`,
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
				Val NullableBoolWrapper `xml:"Val"`
			}
			err := xml.Unmarshal([]byte(c.value), &x)

			if !errors.Is(err, c.expErr) {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if x.Val.Bool != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.Bool)
			}
			if x.Val.Valid != c.expValid {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValid, x.Val.Valid)
			}
		})
	}
}

func TestNullableBoolWrapperUnmarshalXMLAttr(t *testing.T) {
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
			title:    "value is '1'",
			value:    `<Wrap><Val v="1"></Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'enabled'",
			value:    `<Wrap><Val v="enabled"></Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'checked'",
			value:    `<Wrap><Val v="checked"></Val></Wrap>`,
			expValue: true,
			expValid: true,
			expErr:   nil,
		},
		{
			title:    "value is 'yes'",
			value:    `<Wrap><Val v="yes"></Val></Wrap>`,
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
					Content string              `xml:",chardata"`
					V       NullableBoolWrapper `xml:"v,attr,omitempty"`
				}
			}
			err := xml.Unmarshal([]byte(c.value), &x)

			if !errors.Is(err, c.expErr) {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}
			if x.Val.V.Bool != c.expValue {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, x.Val.V.Bool)
			}

			if x.Val.V.Valid != c.expValid {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValid, x.Val.V.Valid)
			}
		})
	}
}
