package gokeepasslib

import (
	"testing"
)
var message string = "Hello World!"

func TestBinary (t *testing.T) {
	binary := Binary{ID:0,Compressed:boolWrapper(true)}
	err := binary.SetContent([]byte(message))
	if err != nil {
		t.Fatalf("Error setting content: %s",err)
	}
	content, err := binary.GetContent()
	if err != nil {
		t.Fatalf("Error getting content: %s",err)
	}
	if content[:] != message[:] {
		t.Fatalf("GetContent should be: `%s`, instead was `%s` ]",message,content)
	}
	
	//Same test, uncompressed
	binary2 := Binary{ID:0,Compressed:boolWrapper(false)}
	err = binary2.SetContent([]byte(message))
	if err != nil {
		t.Fatalf("Error setting content: %s",err)
	}
	content, err = binary2.GetContent()
	if err != nil {
		t.Fatalf("Error getting content: %s",err)
	}
	if content[:] != message[:] {
		t.Fatalf("GetContent should be: `%s`, instead was `%s` ]",message,content)
	}
}