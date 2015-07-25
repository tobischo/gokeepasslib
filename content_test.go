package gokeepasslib

import (
	"testing"
	"time"
)

func TestNewTimeData(t *testing.T) {
	timeData := NewTimeData()
	if time.Since(*timeData.CreationTime) > time.Millisecond {
		t.Error("CreationTime not properly initialized: should be time.Now()")
	}
	if time.Since(*timeData.LastModificationTime) > time.Millisecond {
		t.Error("LastModificationTime not properly initialized: should be time.Now()")
	}
	if time.Since(*timeData.LastAccessTime) > time.Millisecond {
		t.Error("LastAccessTime not properly initialized: should be time.Now()")
	}
	if timeData.ExpiryTime != nil {
		t.Error("ExpiryTime not properly initialized: should be nil")
	}
	if time.Since(*timeData.LocationChanged) > time.Millisecond {
		t.Error("LocationChanged not properly initialized: should be time.Now()")
	}
}
