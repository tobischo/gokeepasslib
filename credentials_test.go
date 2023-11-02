package gokeepasslib

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"
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
			cryptAESKey(c.masterKey, c.seed, c.rounds)
			result, err := cryptAESKey2(c.masterKey, c.seed, c.rounds)

			if !bytes.Equal(result, c.expectedResult) {
				t.Errorf("Received % X, expected % X", result, c.expectedResult)
			}

			if !reflect.DeepEqual(err, c.expectedError) {
				t.Errorf("Received %v, expected %v", err, c.expectedError)
			}
		})
	}
}

func TestParseKeyFile(t *testing.T) {
	cases := []struct {
		title          string
		keyFilePath    string
		expectedResult []byte
		expectedError  error
	}{
		{
			title:       "with a simple keyfile with a non 32 byte key",
			keyFilePath: "tests/keyfiles/txt_derive.key",
			expectedResult: []byte{
				0xfe, 0x0d, 0xbe, 0xdd, 0x5d, 0xee, 0x00, 0xab,
				0x5c, 0x92, 0x8b, 0x5e, 0xae, 0xfe, 0x94, 0x25,
				0xe8, 0x1d, 0x1d, 0xfa, 0x8c, 0x03, 0xfa, 0x65,
				0x46, 0x9f, 0x18, 0xad, 0x13, 0xb9, 0x8e, 0x89,
			},
		},
		{
			title:       "with a simple keyfile with a 32 byte key",
			keyFilePath: "tests/keyfiles/bin_32_byte.key",
			expectedResult: []byte{
				0xcd, 0x1c, 0x63, 0xc8, 0xc7, 0x43, 0xca, 0xea,
				0x12, 0xc5, 0x89, 0x9b, 0xd9, 0x5c, 0xc5, 0xb2,
				0xac, 0x1d, 0x53, 0x37, 0x92, 0x5a, 0xca, 0x37,
				0x5a, 0x7e, 0x6a, 0x83, 0x34, 0x4c, 0x9c, 0x45,
			},
		},
		{
			title:       "with a simple keyfile with a 64 byte key that is not hex",
			keyFilePath: "tests/keyfiles/non_hex_64_byte.key",
			expectedResult: []byte{
				0x9F, 0x82, 0x86, 0x7C, 0xF3, 0xF0, 0xE1, 0x4D,
				0xBD, 0xF8, 0xD3, 0x9F, 0xB0, 0xDD, 0xDF, 0x93,
				0x0C, 0xA8, 0x34, 0x39, 0x38, 0x1C, 0xFB, 0xA4,
				0xBF, 0xA6, 0xD2, 0xBE, 0x2F, 0x72, 0xEB, 0xBF,
			},
		},
		{
			title:       "with a simple keyfile with a 64 byte key that is hex",
			keyFilePath: "tests/keyfiles/hex_64_byte.key",
			expectedResult: []byte{
				0x28, 0x3b, 0x13, 0xa4, 0x4b, 0x98, 0x08, 0x3b,
				0x16, 0x1e, 0xb5, 0xf4, 0xd6, 0x96, 0xec, 0xf6,
				0x8c, 0x92, 0x3a, 0x7c, 0x32, 0xbd, 0x88, 0xc3,
				0xa4, 0x24, 0x0c, 0x33, 0xb3, 0xf1, 0x63, 0x35,
			},
		},
		{
			title:       "with an XML keyfile with format v1.00",
			keyFilePath: "tests/keyfiles/xml_v1.00.key",
			expectedResult: []byte{
				0x3d, 0xb2, 0xc1, 0x62, 0x68, 0x04, 0x5c, 0x58,
				0x4b, 0x59, 0xfd, 0xa0, 0xc6, 0x80, 0x4c, 0x01,
				0x15, 0xe0, 0x0d, 0x91, 0x84, 0xed, 0xfd, 0xf8,
				0xb6, 0xbf, 0x9a, 0x9c, 0x2c, 0x39, 0xd8, 0xb2,
			},
		},
		{
			title:       "with an XML keyfile with format v1.0",
			keyFilePath: "tests/keyfiles/xml_v1.0.key",
			expectedResult: []byte{
				0x3d, 0xb2, 0xc1, 0x62, 0x68, 0x04, 0x5c, 0x58,
				0x4b, 0x59, 0xfd, 0xa0, 0xc6, 0x80, 0x4c, 0x01,
				0x15, 0xe0, 0x0d, 0x91, 0x84, 0xed, 0xfd, 0xf8,
				0xb6, 0xbf, 0x9a, 0x9c, 0x2c, 0x39, 0xd8, 0xb2,
			},
		},
		{
			title:         "with an XML keyfile with format v2.0 and an invalid hash",
			keyFilePath:   "tests/keyfiles/xml_v2.0_invalid_hash.key",
			expectedError: errKeyHashMismatch,
		},
		{
			title:       "with an XML keyfile with format v2.0",
			keyFilePath: "tests/keyfiles/xml_v2.0.key",
			expectedResult: []byte{
				0x67, 0x71, 0x52, 0x1d, 0x64, 0x4d, 0xfa, 0x15,
				0xf3, 0x9c, 0x17, 0x73, 0x47, 0xcb, 0x28, 0xac,
				0xc4, 0xd1, 0x09, 0x94, 0xc0, 0xba, 0xbf, 0xd9,
				0xb8, 0xf1, 0xe1, 0x32, 0xa1, 0x42, 0x70, 0x97,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			result, err := ParseKeyFile(c.keyFilePath)

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

func TestSpeed(t *testing.T) {
	start := time.Now()
	cryptAESKey(
		[]byte("8ee89711330c1ccf39a2e65ad12bbd7d"),
		[]byte("a25ca73c7189e2a2ca5acf2088b57e28"),
		60_000_000)
	elapsed := time.Since(start)
	t.Log(elapsed)
}
