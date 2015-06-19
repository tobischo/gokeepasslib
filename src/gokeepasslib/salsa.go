package gokeepasslib

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

var SALSA_IV = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}
var SIGMA_WORDS = []int{
	0x61707865,
	0x3320646e,
	0x79622d32,
	0x6b206574,
}
var ROUNDS = 20

func UnlockProtectedEntry(e *Entry, d *Database) []byte {
	key := sha256.Sum256(d.headers.ProtectedStreamKey)
	salsaManager := NewSalsaManager(key[:])
	return salsaManager.unpack(e.getPassword())
}

type SalsaManager struct {
	Key          []byte
	Nonce        []byte
	blockUsed    int
	block        []byte
	counterWords [2]int
}

func NewSalsaManager(key []byte) SalsaManager {
	keyWords := [8]byte{}
	j := 0
	for i := 0; i < 8; i++ {
		keyWords[i] = ((key[j+0] & 0xff) << 0) |
			((key[j+1] & 0xff) << 8) |
			((key[j+2] & 0xff) << 16) |
			((key[j+3] & 0xff) << 24)
		j += 4
	}

	nonceWords := [2]byte{}
	nonceWords[0] = ((SALSA_IV[0] & 0xff) << 0) |
		((SALSA_IV[1] & 0xff) << 8) |
		((SALSA_IV[2] & 0xff) << 16) |
		((SALSA_IV[3] & 0xff) << 24)
	nonceWords[1] = ((SALSA_IV[4] & 0xff) << 0) |
		((SALSA_IV[5] & 0xff) << 8) |
		((SALSA_IV[6] & 0xff) << 16) |
		((SALSA_IV[7] & 0xff) << 24)

	s := SalsaManager{
		Key:   keyWords[:],
		Nonce: nonceWords[:],
	}
	s.reset()
	return s
}

func (s *SalsaManager) unpack(payload string) []byte {
	result := make([]byte, 0)

	data, _ := base64.StdEncoding.DecodeString(payload)

	salsaBytes := s.getBytes(len(data))
	fmt.Printf("% x\n", salsaBytes)
	//[ 86, 184, 90, 22, 209 ]
	for i := 0; i < len(data); i++ {
		result = append(result, salsaBytes[i]^data[i])
	}

	return result
}

func (s *SalsaManager) reset() {
	s.blockUsed = 64
	s.counterWords = [2]int{0, 0}
}

func (s *SalsaManager) incrementCounter() {
	s.counterWords[0] = (s.counterWords[0] + 1) & 0xffffffff
	if s.counterWords[0] == 0 {
		s.counterWords[1] = (s.counterWords[1] + 1) & 0xffffffff
	}
}

func (s *SalsaManager) getBytes(length int) []byte {
	b := make([]byte, length)

	for i := 0; i < length; i++ {
		if s.blockUsed == 64 {
			s.generateBlock()
			s.incrementCounter()
			s.blockUsed = 0
		}
		b[i] = s.block[s.blockUsed]
		s.blockUsed++
	}

	return b
}

func (s *SalsaManager) generateBlock() {
	s.block = make([]byte, 64)

	j0 := SIGMA_WORDS[0]
	j1 := int(s.Key[0])
	j2 := int(s.Key[1])
	j3 := int(s.Key[2])
	j4 := int(s.Key[3])
	j5 := SIGMA_WORDS[1]
	j6 := int(s.Nonce[0])
	j7 := int(s.Nonce[1])
	j8 := int(s.counterWords[0])
	j9 := int(s.counterWords[1])
	j10 := SIGMA_WORDS[2]
	j11 := int(s.Key[4])
	j12 := int(s.Key[5])
	j13 := int(s.Key[6])
	j14 := int(s.Key[7])
	j15 := SIGMA_WORDS[3]
	x0 := j0
	x1 := j1
	x2 := j2
	x3 := j3
	x4 := j4
	x5 := j5
	x6 := j6
	x7 := j7
	x8 := j8
	x9 := j9
	x10 := j10
	x11 := j11
	x12 := j12
	x13 := j13
	x14 := j14
	x15 := j15

	for i := 0; i < ROUNDS; i = i + 2 {
		// First block
		x4 = x4 ^ ((x0 + x12) << 7) | ((x0 + x12) >> (32 - 7))
		x8 = x8 ^ ((x4 + x0) << 9) | ((x4 + x0) >> (32 - 9))
		x12 = x12 ^ ((x8 + x4) << 13) | ((x8 + x4) >> (32 - 13))
		x0 = x0 ^ ((x12 + x8) << 18) | ((x12 + x8) >> (32 - 18))

		// Second block
		x9 = x9 ^ ((x5 + x1) << 7) | ((x5 + x1) >> (32 - 7))
		x13 = x13 ^ ((x9 + x5) << 9) | ((x9 + x5) >> (32 - 9))
		x1 = x1 ^ ((x13 + x9) << 13) | ((x13 + x9) >> (32 - 13))
		x5 = x5 ^ ((x1 + x13) << 18) | ((x1 + x13) >> (32 - 18))

		// Third block
		x14 = x14 ^ ((x10 + x6) << 7) | ((x10 + x6) >> (32 - 7))
		x2 = x2 ^ ((x14 + x10) << 9) | ((x14 + x10) >> (32 - 9))
		x6 = x6 ^ ((x2 + x14) << 13) | ((x2 + x14) >> (32 - 13))
		x10 = x10 ^ ((x6 + x2) << 18) | ((x6 + x2) >> (32 - 18))

		// Fourth block
		x3 = x3 ^ ((x15 + x11) << 7) | ((x15 + x11) >> (32 - 7))
		x7 = x7 ^ ((x3 + x15) << 9) | ((x3 + x15) >> (32 - 9))
		x11 = x11 ^ ((x7 + x3) << 13) | ((x7 + x3) >> (32 - 13))
		x15 = x15 ^ ((x11 + x7) << 18) | ((x11 + x7) >> (32 - 18))

		// Fifth block
		x1 = x1 ^ ((x0 + x3) << 7) | ((x0 + x3) >> (32 - 7))
		x2 = x2 ^ ((x1 + x0) << 9) | ((x1 + x0) >> (32 - 9))
		x3 = x3 ^ ((x2 + x1) << 13) | ((x2 + x1) >> (32 - 13))
		x0 = x0 ^ ((x3 + x2) << 18) | ((x3 + x2) >> (32 - 18))

		// Sixth block
		x6 = x6 ^ ((x5 + x4) << 7) | ((x5 + x4) >> (32 - 7))
		x7 = x7 ^ ((x6 + x5) << 9) | ((x6 + x5) >> (32 - 9))
		x4 = x4 ^ ((x7 + x6) << 13) | ((x7 + x6) >> (32 - 13))
		x5 = x5 ^ ((x4 + x7) << 18) | ((x4 + x7) >> (32 - 18))

		// Seventh block
		x11 = x11 ^ ((x10 + x9) << 7) | ((x10 + x9) >> (32 - 7))
		x8 = x8 ^ ((x11 + x10) << 9) | ((x11 + x10) >> (32 - 9))
		x9 = x9 ^ ((x8 + x11) << 13) | ((x8 + x11) >> (32 - 13))
		x10 = x10 ^ ((x9 + x8) << 18) | ((x9 + x8) >> (32 - 18))

		// Eigth block
		x12 = x12 ^ ((x15 + x14) << 7) | ((x15 + x14) >> (32 - 7))
		x13 = x13 ^ ((x12 + x15) << 9) | ((x12 + x15) >> (32 - 9))
		x14 = x14 ^ ((x13 + x12) << 13) | ((x13 + x12) >> (32 - 13))
		x15 = x15 ^ ((x14 + x13) << 18) | ((x14 + x13) >> (32 - 18))
	}

	x0 += j0
	x1 += j1
	x2 += j2
	x3 += j3
	x4 += j4
	x5 += j5
	x6 += j6
	x7 += j7
	x8 += j8
	x9 += j9
	x10 += j10
	x11 += j11
	x12 += j12
	x13 += j13
	x14 += j14
	x15 += j15

	s.block[0] = byte((x0 >> 0) & 0xff)
	s.block[1] = byte((x0 >> 8) & 0xff)
	s.block[2] = byte((x0 >> 16) & 0xff)
	s.block[3] = byte((x0 >> 24) & 0xff)
	s.block[4] = byte((x1 >> 0) & 0xff)
	s.block[5] = byte((x1 >> 8) & 0xff)
	s.block[6] = byte((x1 >> 16) & 0xff)
	s.block[7] = byte((x1 >> 24) & 0xff)
	s.block[8] = byte((x2 >> 0) & 0xff)
	s.block[9] = byte((x2 >> 8) & 0xff)
	s.block[10] = byte((x2 >> 16) & 0xff)
	s.block[11] = byte((x2 >> 24) & 0xff)
	s.block[12] = byte((x3 >> 0) & 0xff)
	s.block[13] = byte((x3 >> 8) & 0xff)
	s.block[14] = byte((x3 >> 16) & 0xff)
	s.block[15] = byte((x3 >> 24) & 0xff)
	s.block[16] = byte((x4 >> 0) & 0xff)
	s.block[17] = byte((x4 >> 8) & 0xff)
	s.block[18] = byte((x4 >> 16) & 0xff)
	s.block[19] = byte((x4 >> 24) & 0xff)
	s.block[20] = byte((x5 >> 0) & 0xff)
	s.block[21] = byte((x5 >> 8) & 0xff)
	s.block[22] = byte((x5 >> 16) & 0xff)
	s.block[23] = byte((x5 >> 24) & 0xff)
	s.block[24] = byte((x6 >> 0) & 0xff)
	s.block[25] = byte((x6 >> 8) & 0xff)
	s.block[26] = byte((x6 >> 16) & 0xff)
	s.block[27] = byte((x6 >> 24) & 0xff)
	s.block[28] = byte((x7 >> 0) & 0xff)
	s.block[29] = byte((x7 >> 8) & 0xff)
	s.block[30] = byte((x7 >> 16) & 0xff)
	s.block[31] = byte((x7 >> 24) & 0xff)
	s.block[32] = byte((x8 >> 0) & 0xff)
	s.block[33] = byte((x8 >> 8) & 0xff)
	s.block[34] = byte((x8 >> 16) & 0xff)
	s.block[35] = byte((x8 >> 24) & 0xff)
	s.block[36] = byte((x9 >> 0) & 0xff)
	s.block[37] = byte((x9 >> 8) & 0xff)
	s.block[38] = byte((x9 >> 16) & 0xff)
	s.block[39] = byte((x9 >> 24) & 0xff)
	s.block[40] = byte((x10 >> 0) & 0xff)
	s.block[41] = byte((x10 >> 8) & 0xff)
	s.block[42] = byte((x10 >> 16) & 0xff)
	s.block[43] = byte((x10 >> 24) & 0xff)
	s.block[44] = byte((x11 >> 0) & 0xff)
	s.block[45] = byte((x11 >> 8) & 0xff)
	s.block[46] = byte((x11 >> 16) & 0xff)
	s.block[47] = byte((x11 >> 24) & 0xff)
	s.block[48] = byte((x12 >> 0) & 0xff)
	s.block[49] = byte((x12 >> 8) & 0xff)
	s.block[50] = byte((x12 >> 16) & 0xff)
	s.block[51] = byte((x12 >> 24) & 0xff)
	s.block[52] = byte((x13 >> 0) & 0xff)
	s.block[53] = byte((x13 >> 8) & 0xff)
	s.block[54] = byte((x13 >> 16) & 0xff)
	s.block[55] = byte((x13 >> 24) & 0xff)
	s.block[56] = byte((x14 >> 0) & 0xff)
	s.block[57] = byte((x14 >> 8) & 0xff)
	s.block[58] = byte((x14 >> 16) & 0xff)
	s.block[59] = byte((x14 >> 24) & 0xff)
	s.block[60] = byte((x15 >> 0) & 0xff)
	s.block[61] = byte((x15 >> 8) & 0xff)
	s.block[62] = byte((x15 >> 16) & 0xff)
	s.block[63] = byte((x15 >> 24) & 0xff)

}
