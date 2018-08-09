package gokeepasslib

import (
	"errors"
	"time"
)

var errYearOutsideOfRange = errors.New("TimeWrapper.MarshalText: year outside of range [0,9999]")

type TimeWrapper time.Time

// Now returns a TimeWrapper instance with the current time in UTC
func Now() TimeWrapper {
	return TimeWrapper(time.Now().In(time.UTC))
}

// MarshalText marshals time into an RFC3339 compliant value in UTC
func (tw TimeWrapper) MarshalText() ([]byte, error) {
	t := time.Time(tw).In(time.UTC)
	if y := t.Year(); y < 0 || y >= 10000 {
		return nil, errYearOutsideOfRange
	}

	b := make([]byte, 0, len(time.RFC3339))
	return t.AppendFormat(b, time.RFC3339), nil
}

// UnmarshalText take a string of format time.RFC3339 and marshals it into the TimeWrapper value.
func (tw *TimeWrapper) UnmarshalText(data []byte) error {
	// Fractional seconds are handled implicitly by Parse.
	t, err := time.Parse(time.RFC3339, string(data))
	*tw = TimeWrapper(t)
	return err
}
