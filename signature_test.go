package gokeepasslib

import "testing"

func TestBaseSignature(t *testing.T) {
	expectedSignature := [4]byte{0x03, 0xd9, 0xa2, 0x9a}
	if BaseSignature != expectedSignature {
		t.Fatalf(
			"BaseSignature not valid: got %x, expected %x",
			BaseSignature,
			expectedSignature,
		)
	}
}

func TestSecondarySignature(t *testing.T) {
	expectedSignature := [4]byte{0x67, 0xfb, 0x4b, 0xb5}
	if SecondarySignature != expectedSignature {
		t.Fatalf(
			"SecondarySignature not valid: got %x, expected %x",
			SecondarySignature,
			expectedSignature,
		)
	}
}

func TestValidate(t *testing.T) {
	signature := FileSignature{}
	if err := signature.Validate(); err == nil || err.(ErrInvalidSignature).Name != "Base Signature" {
		t.Fatal("Base Signature is valid although it should not be")
	}
	signature.BaseSignature = BaseSignature

	if err := signature.Validate(); err == nil || err.(ErrInvalidSignature).Name != "Secondary Signature" {
		t.Fatal("Secondary Signature is valid although it should not be")
	}
	signature.SecondarySignature = SecondarySignature

	if err := signature.Validate(); err == nil || err.(ErrInvalidSignature).Name != "Minor Version" {
		t.Fatal("MinorVersion is valid although it should not be")
	}
	signature.MinorVersion = MinorVersion

	if err := signature.Validate(); err == nil || err.(ErrInvalidSignature).Name != "Major Version" {
		t.Fatal("MajorVersion is valid although it should not be")
	}
	signature.MajorVersion = MajorVersion

	if err := signature.Validate(); err != nil {
		t.Fatal("signature is invalid although it should not be")
	}
}

func TestErrInvalidSignature(t *testing.T) {
	err := ErrInvalidSignature{
		"Base Signature",
		[...]byte{0x01, 0x02, 0x03, 0x04},
		BaseSignature,
	}

	if err.Error() != "gokeepasslib: invalid signature. Base Signature is 01020304. Should be 03d9a29a" {
		t.Fatal("ErrInvalidSignatue not stringified correctly")
	}
}

func TestFileSignatureString(t *testing.T) {
	signature := FileSignature{}
	if signature.String() != "Base: 00000000, Secondary: 00000000, Format Version: 0.0" {
		t.Fatal("Signature not stringified correctly")
	}
}
