package gokeepass_lib

import (
	"encoding/binary"
	"io"
)

type Decoder struct {
	r io.Reader
}

func (d *Decoder) Decode(db *Database) error {
	if err := d.readSignature(db); err != nil {
		return err
	}

	if err := d.readHeaders(db); err != nil {
		return err
	}

	return nil
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

func (d *Decoder) readSignature(db *Database) error {
	sig := new(Signature)
	if err := binary.Read(d.r, binary.LittleEndian, sig); err != nil {
		return err
	}
	db.signature = *sig
	return nil
}

func (d *Decoder) readHeaders(db *Database) error {
	headers := new(Headers)

	for {
		var fieldID byte
		if err := binary.Read(d.r, binary.LittleEndian, &fieldID); err != nil {
			return err
		}

		var fieldLength [2]byte
		if err := binary.Read(d.r, binary.LittleEndian, &fieldLength); err != nil {
			return err
		}

		var fieldData = make([]byte, binary.LittleEndian.Uint16(fieldLength[:]))
		if err := binary.Read(d.r, binary.LittleEndian, &fieldData); err != nil {
			return err
		}

		switch fieldID {
		case 1:
			headers.Comment = fieldData
		case 2:
			headers.CipherID = fieldData
		case 3:
			headers.CompressionFlags = binary.LittleEndian.Uint32(fieldData)
		case 4:
			headers.MasterSeed = fieldData
		case 5:
			headers.TransformSeed = fieldData
		case 6:
			data := binary.LittleEndian.Uint32(fieldData[4:8])*
				(1<<16)*(1<<16) +
				binary.LittleEndian.Uint32(fieldData[0:4])
			headers.TransformRounds = data
		case 7:
			headers.EncryptionIV = fieldData
		case 8:
			headers.ProtectedStreamKey = fieldData
		case 9:
			headers.StreamStartBytes = fieldData
		case 10:
			headers.InnerRandomStreamID = fieldData
		}

		if fieldID == 0 {
			break
		}
	}

	db.headers = *headers
	return nil
}
