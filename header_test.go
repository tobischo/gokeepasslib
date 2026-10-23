package gokeepasslib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestReadFileHeaderCorrupted(t *testing.T) {
	cases := []struct {
		title string
		id    uint8
		data  []byte
	}{
		{
			title: "compression flags too short",
			id:    headerIDCompressionsFlags,
			data:  []byte{0x01},
		},
		{
			title: "transform rounds too short",
			id:    headerIDTransformRounds,
			data:  []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			title: "inner random stream ID missing",
			id:    headerIDInnerRandomStream,
			data:  []byte{},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			err := new(FileHeaders).readFileHeader(c.id, c.data)
			if !errors.Is(err, ErrCorruptedDatabase) {
				t.Fatalf("Received error '%v', expected '%v'", err, ErrCorruptedDatabase)
			}
		})
	}
}

func TestReadKdfParametersCorrupted(t *testing.T) {
	cases := []struct {
		title string
		name  string
		value []byte
	}{
		{
			title: "rounds too short",
			name:  "R",
			value: []byte{0x01},
		},
		{
			title: "salt too short",
			name:  "S",
			value: bytes.Repeat([]byte{0x01}, 16),
		},
		{
			title: "parallelism missing",
			name:  "P",
			value: []byte{},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			var data bytes.Buffer
			binary.Write(&data, binary.LittleEndian, uint16(0x0100))
			data.WriteByte(0x42)
			binary.Write(&data, binary.LittleEndian, int32(len(c.name)))
			data.WriteString(c.name)
			binary.Write(&data, binary.LittleEndian, int32(len(c.value)))
			data.Write(c.value)
			data.WriteByte(0x00)

			err := new(KdfParameters).readKdfParameters(data.Bytes())
			if !errors.Is(err, ErrCorruptedDatabase) {
				t.Fatalf("Received error '%v', expected '%v'", err, ErrCorruptedDatabase)
			}
		})
	}
}

func TestReadVariantDictionaryNegativeLength(t *testing.T) {
	var data bytes.Buffer
	binary.Write(&data, binary.LittleEndian, uint16(0x0100))
	data.WriteByte(0x42)
	binary.Write(&data, binary.LittleEndian, int32(-1))

	err := new(VariantDictionary).readVariantDictionary(data.Bytes())
	if !errors.Is(err, ErrCorruptedDatabase) {
		t.Fatalf("Received error '%v', expected '%v'", err, ErrCorruptedDatabase)
	}
}
