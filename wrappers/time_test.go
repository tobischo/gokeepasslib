package wrappers

import (
	"testing"
	"time"
)

func TestNow(t *testing.T) {
	cases := []struct {
		title               string
		options             []TimeOption
		expectedTimeWrapper TimeWrapper
	}{
		{
			title: "without options",
			expectedTimeWrapper: TimeWrapper{
				Formatted: true,
				Time:      time.Now().In(time.UTC),
			},
		},
		{
			title:   "with formatting false",
			options: []TimeOption{WithFormatted(false)},
			expectedTimeWrapper: TimeWrapper{
				Formatted: false,
				Time:      time.Now().In(time.UTC),
			},
		},
		{
			title:   "with kdbx4 formatting",
			options: []TimeOption{WithKDBX4Formatting},
			expectedTimeWrapper: TimeWrapper{
				Formatted: false,
				Time:      time.Now().In(time.UTC),
			},
		},
		{
			title: "with time overwrite",
			options: []TimeOption{
				func(t *TimeWrapper) {
					t.Time = time.Date(2015, 11, 12, 23, 34, 34, 0, time.UTC)
				},
			},
			expectedTimeWrapper: TimeWrapper{
				Formatted: true,
				Time:      time.Date(2015, 11, 12, 23, 34, 34, 0, time.UTC),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			timeWrapper := Now(c.options...)

			if timeWrapper.Formatted != c.expectedTimeWrapper.Formatted {
				t.Errorf(
					"Received formatted %+v, expected %+v",
					timeWrapper.Formatted,
					c.expectedTimeWrapper.Formatted,
				)
			}

			duration, _ := time.ParseDuration("100ms")

			if timeWrapper.Time.Sub(c.expectedTimeWrapper.Time) > duration {
				t.Errorf(
					"Received time not within %+v: received %+v, expected %+v",
					duration,
					timeWrapper.Time,
					c.expectedTimeWrapper.Time,
				)
			}
		})
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
