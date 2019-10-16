package gokeepasslib

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestCryptAESKey(t *testing.T) {

	cases := []struct {
		title     string
		masterKey []byte
		seed      []byte
		rounds    uint64

		expectedResult []byte
		expectedError  error
	}{
		{
			title:     "example 1",
			masterKey: []byte("8ee89711330c1ccf39a2e65ad12bbd7d"),
			seed:      []byte("a25ca73c7189e2a2ca5acf2088b57e28"),
			rounds:    6000,

			expectedResult: []byte{
				0x2f, 0xfa, 0x2c, 0x11, 0xeb, 0x4a, 0xcc, 0xe3,
				0x45, 0xd9, 0x9b, 0x53, 0xab, 0x4b, 0x71, 0x9c,
				0xbe, 0x3a, 0x8c, 0x80, 0x99, 0x6f, 0xc7, 0xae,
				0xb5, 0xde, 0x76, 0xef, 0x3e, 0x4c, 0x2d, 0x57,
			},
		},
		{
			title:     "example 2",
			masterKey: []byte("553295e4b848bee781c30a0c86a5b731"),
			seed:      []byte("7ce5fcd046004c9f93dea6b3c2effd72"),
			rounds:    3000,

			expectedResult: []byte{
				0xb4, 0xc7, 0x2d, 0x05, 0x81, 0xf4, 0x0a, 0x2f,
				0xc7, 0x50, 0x57, 0x4f, 0x52, 0x4e, 0x5a, 0x12,
				0x35, 0x36, 0x85, 0x17, 0x5e, 0xd7, 0x54, 0x48,
				0x95, 0x8b, 0x3e, 0xfe, 0x37, 0x62, 0xde, 0x24,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			result, err := cryptAESKey(c.masterKey, c.seed, c.rounds)

			if !bytes.Equal(result, c.expectedResult) {
				t.Errorf("Received % X, expected % X", result, c.expectedResult)
			}

			if !reflect.DeepEqual(err, c.expectedError) {
				t.Errorf("Received %v, expected %v", err, c.expectedError)
			}
		})
	}
}

func BenchmarkCryptAESKey(b *testing.B) {
	cases := []struct {
		title     string
		masterKey []byte
		seed      []byte
		rounds    uint64

		expectedResult []byte
		expectedError  error
	}{
		{
			title:     "example 1",
			masterKey: []byte("8ee89711330c1ccf39a2e65ad12bbd7d"),
			seed:      []byte("a25ca73c7189e2a2ca5acf2088b57e28"),
			rounds:    6000,
		},
		{
			title:     "example 2",
			masterKey: []byte("553295e4b848bee781c30a0c86a5b731"),
			seed:      []byte("7ce5fcd046004c9f93dea6b3c2effd72"),
			rounds:    3000,
		},
		{
			title:     "example 3",
			masterKey: []byte("553295e4b848bee781c30a0c86a5b731"),
			seed:      []byte("7ce5fcd046004c9f93dea6b3c2effd72"),
			rounds:    12000,
		},
	}

	for _, c := range cases {
		b.Run(c.title, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := cryptAESKey(c.masterKey, c.seed, c.rounds)
				if err != nil {
					fmt.Printf("error: %v", err)
				}
			}
		})
	}

}
