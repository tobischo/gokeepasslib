package gokeepasslib

import (
	"encoding/base64"
	"golang.org/x/crypto/salsa20"
)

var iv = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}

type SalsaManger struct {
	key [32]byte
}
func NewSalsaManager (key [32]byte) SalsaManger {
	return SalsaManger{key}
}
func (m SalsaManger) Unpack (payload string) []byte {
	in,_ := base64.StdEncoding.DecodeString(payload)
	out := make([]byte,len(in))
	salsa20.XORKeyStream(out,in,iv,&m.key)
	return out
}
func (m SalsaManger) Pack (payload []byte) string {
	out := make([]byte,len(payload))
	salsa20.XORKeyStream(out,payload,iv,&m.key)
	return base64.StdEncoding.EncodeToString(out)
}