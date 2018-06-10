package gokeepasslib

import (
	"fmt"
	"testing"
	"time"
)

func TestTimeWrapperNow(t *testing.T) {
	now := time.Now().In(time.UTC)
	timeWrapNow := Now()

	fmt.Println(time.Time(timeWrapNow).Sub(now))

	if time.Time(timeWrapNow).Sub(now) > time.Second {
		t.Errorf("Now did not return the current time")
	}
}

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
			expErr: errYearOutsideOfRange,
		},
		{
			title: "year above 10000",
			valueFn: func() time.Time {
				return time.Date(10001, time.June, 10, 6, 34, 12, 123123, time.UTC)
			},
			expErr: errYearOutsideOfRange,
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

			data, err := timeWrapper(value).MarshalText()
			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}

			if string(data) != c.expValue {
				t.Errorf("Did not marshal into expected string '%s', received: '%s'", c.expValue, string(data))
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

			timeWrap := &timeWrapper{}
			err := timeWrap.UnmarshalText([]byte(c.value))
			if err != c.expErr {
				t.Fatalf("Did not receive expected error %+v, received %+v", c.expErr, err)
			}

			if !time.Time(*timeWrap).Equal(c.expValue) {
				t.Errorf("Did not receive expected value '%+v', received: '%+v'", c.expValue, *timeWrap)
			}
		})
	}
}
