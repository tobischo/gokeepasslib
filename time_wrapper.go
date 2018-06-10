package gokeepasslib

import (
	"errors"
	"time"
)

var errYearOutsideOfRange = errors.New("timeWrapper.MarshalText: year outside of range [0,9999]")

type timeWrapper time.Time

// Now returns a timeWrapper instance with the current time in UTC
func Now() timeWrapper {
	return timeWrapper(time.Now().In(time.UTC))
}

// MarshalText marshals time into an RFC3339 compliant value in UTC
func (tw timeWrapper) MarshalText() ([]byte, error) {
	t := time.Time(tw).In(time.UTC)
	if y := t.Year(); y < 0 || y >= 10000 {
		return nil, errYearOutsideOfRange
	}

	b := make([]byte, 0, len(time.RFC3339))
	return t.AppendFormat(b, time.RFC3339), nil
}

// UnmarshalText take a string of format time.RFC3339 and marshals it into the timeWrapper value.
func (tw *timeWrapper) UnmarshalText(data []byte) error {
	// Fractional seconds are handled implicitly by Parse.
	t, err := time.Parse(time.RFC3339, string(data))
	*tw = timeWrapper(t)
	return err
}
