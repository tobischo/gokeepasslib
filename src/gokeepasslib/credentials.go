package gokeepasslib

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

type Credentials struct {
	Key      []byte
	Priority int32
}

func (c *Credentials) String() string {
	return fmt.Sprintf("%x", c.Key)
}

func NewPasswordCredentials(password string) *Credentials {
	credentials := &Credentials{Priority: 200}
	key := sha256.Sum256([]byte(password))
	credentials.Key = key[:]
	return credentials
}

func NewKeyCredentials(location string) (*Credentials, error) {
	credentials := &Credentials{Priority: 100}
	r, err := regexp.Compile("<data>(.+)<\\/data>")
	if err != nil {
		return nil, err
	}
	file, err := os.Open(location)
	if err != nil {
		return nil, err
	}
	var data []byte
	if data, err = ioutil.ReadAll(file); err != nil {
		return nil, err
	}

	if r.Match(data) {
		credentials.Key = r.FindSubmatch(data)[1]
	} else {
		key := sha256.Sum256(data)
		credentials.Key = key[:]
	}
	return credentials, nil
}