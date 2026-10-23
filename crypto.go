package gokeepasslib

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/tobischo/gokeepasslib/v3/crypto"
)

// Constant enumerator for the inner random stream ID
const (
	NoStreamID     uint32 = 0 // ID for non-protection
	ARC4StreamID   uint32 = 1 // ID for ARC4 protection, not implemented
	SalsaStreamID  uint32 = 2 // ID for Salsa20 protection
	ChaChaStreamID uint32 = 3 // ID for ChaCha20 protection
)

// EncrypterManager is the manager to handle an Encrypter
type EncrypterManager struct {
	Encrypter Encrypter
}

// Encrypter is responsible for database encrypting and decrypting
type Encrypter interface {
	Decrypt(data []byte) []byte
	Encrypt(data []byte) []byte
}

// StreamManager is the manager to handle a Stream
type StreamManager struct {
	Stream Stream
}

// Stream is responsible for stream encrypting and decrypting of protected fields
type Stream interface {
	Unpack(payload string) []byte
	Pack(payload []byte) string
}

// NewEncrypterManager initialize a new EncrypterManager
func NewEncrypterManager(
	cipherID []byte,
	key []byte,
	iv []byte,
) (*EncrypterManager, error) {
	switch {
	case bytes.Equal(cipherID, CipherChaCha20):
		// ChaCha20
		encrypter, err := crypto.NewChaChaEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	case bytes.Equal(cipherID, CipherTwoFish):
		// TwoFish
		encrypter, err := crypto.NewTwoFishEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	case bytes.Equal(cipherID, CipherAES):
		// AES
		encrypter, err := crypto.NewAESEncrypter(key, iv)
		if err != nil {
			return nil, err
		}

		return &EncrypterManager{
			Encrypter: encrypter,
		}, nil
	default:
		return nil, ErrUnsupportedEncrypterType
	}
}

// cipherBlockSize returns the block size of the block cipher with the given
// cipher ID, or 0 for a stream cipher
func cipherBlockSize(cipherID []byte) int {
	switch {
	case bytes.Equal(cipherID, CipherAES), bytes.Equal(cipherID, CipherTwoFish):
		// AES and TwoFish both use blocks of 128 bits
		return aes.BlockSize
	default:
		return 0
	}
}

// NewStreamManager initialize a new StreamManager
func NewStreamManager(id uint32, key []byte) (*StreamManager, error) {
	switch id {
	case NoStreamID:
		return &StreamManager{
			Stream: crypto.NewInsecureStream(),
		}, nil
	case SalsaStreamID:
		stream, err := crypto.NewSalsaStream(key)
		if err != nil {
			return nil, err
		}

		return &StreamManager{
			Stream: stream,
		}, nil
	case ChaChaStreamID:
		stream, err := crypto.NewChaChaStream(key)
		if err != nil {
			return nil, err
		}

		return &StreamManager{
			Stream: stream,
		}, nil
	default:
		return nil, ErrUnsupportedStreamType
	}
}

// Decrypt returns the decrypted data
func (em *EncrypterManager) Decrypt(data []byte) []byte {
	return em.Encrypter.Decrypt(data)
}

// Encrypt returns the encrypted data
func (em *EncrypterManager) Encrypt(data []byte) []byte {
	return em.Encrypter.Encrypt(data)
}

// Unpack returns the payload as unencrypted byte array
func (cs *StreamManager) Unpack(payload string) []byte {
	return cs.Stream.Unpack(payload)
}

// Pack returns the payload as encrypted string
func (cs *StreamManager) Pack(payload []byte) string {
	return cs.Stream.Pack(payload)
}

// UnlockProtectedGroups unlocks an array of protected groups
func (cs *StreamManager) UnlockProtectedGroups(gs []Group) {
	for i := range gs { // For each top level group
		cs.UnlockProtectedGroup(&gs[i])
	}
}

// UnlockProtectedGroup unlocks a protected group
func (cs *StreamManager) UnlockProtectedGroup(g *Group) {
	// The inner random stream has to be consumed in the order of the XML
	// document, in which some tools interleave entries and groups, e.g. by
	// writing the groups first. This order is recorded during unmarshalling
	var entries, groups int
	for _, child := range g.childOrder {
		switch {
		case child == xmlChildEntry && entries < len(g.Entries):
			cs.UnlockProtectedEntry(&g.Entries[entries])
			entries++
		case child == xmlChildGroup && groups < len(g.Groups):
			cs.UnlockProtectedGroup(&g.Groups[groups])
			groups++
		}
	}

	// Children which were not unmarshalled follow in the order of the struct
	cs.UnlockProtectedEntries(g.Entries[entries:])
	cs.UnlockProtectedGroups(g.Groups[groups:])

	// unset childOrder as for future marshalling the order in the struct superseeds
	// the order in the XML
	g.childOrder = nil
}

// UnlockProtectedEntries unlocks an array of protected entries
func (cs *StreamManager) UnlockProtectedEntries(e []Entry) {
	for i := range e {
		cs.UnlockProtectedEntry(&e[i])
	}
}

// UnlockProtectedEntry unlocks a protected entry
func (cs *StreamManager) UnlockProtectedEntry(e *Entry) {
	// The inner random stream has to be consumed in the order of the XML
	// document, in which some tools write values after the history. This order
	// is recorded during unmarshalling
	var values, histories int
	for _, child := range e.childOrder {
		switch {
		case child == xmlChildValue && values < len(e.Values):
			cs.unlockProtectedValue(&e.Values[values])
			values++
		case child == xmlChildHistory && histories < len(e.Histories):
			cs.UnlockProtectedEntries(e.Histories[histories].Entries)
			histories++
		}
	}

	// Children which were not unmarshalled follow in the order of the struct
	for i := range e.Values[values:] {
		cs.unlockProtectedValue(&e.Values[values+i])
	}
	for i := range e.Histories[histories:] {
		cs.UnlockProtectedEntries(e.Histories[histories+i].Entries)
	}

	// unset childOrder as for future marshalling the order in the struct superseeds
	// the order in the XML
	e.childOrder = nil
}

// unlockProtectedValue unlocks a value if it is protected
func (cs *StreamManager) unlockProtectedValue(v *ValueData) {
	if v.Value.Protected.Bool {
		v.Value.Content = string(cs.Unpack(v.Value.Content))
	}
}

// LockProtectedGroups locks an array of unprotected groups
func (cs *StreamManager) LockProtectedGroups(gs []Group) {
	for i := range gs {
		cs.LockProtectedGroup(&gs[i])
	}
}

// LockProtectedGroup locks an unprotected group
func (cs *StreamManager) LockProtectedGroup(g *Group) {
	cs.LockProtectedEntries(g.Entries)
	cs.LockProtectedGroups(g.Groups)

	// unset childOrder as the values are locked in the order of the struct,
	// which is also the order in which they are marshalled
	g.childOrder = nil
}

// LockProtectedEntries locks an array of unprotected entries
func (cs *StreamManager) LockProtectedEntries(es []Entry) {
	for i := range es {
		cs.LockProtectedEntry(&es[i])
	}
}

// LockProtectedEntry locks an unprotected entry
func (cs *StreamManager) LockProtectedEntry(e *Entry) {
	for i := range e.Values {
		if e.Values[i].Value.Protected.Bool {
			e.Values[i].Value.Content = cs.Pack([]byte(e.Values[i].Value.Content))
		}
	}
	for i := range e.Histories {
		cs.LockProtectedEntries(e.Histories[i].Entries)
	}

	// unset childOrder as the values are locked in the order of the struct,
	// which is also the order in which they are marshalled
	e.childOrder = nil
}

// unlockProtectedBinaries unlocks the stream-protected binaries of a KDBX v3.1
// metadata section, replacing the stream-encrypted content with plain base64
// encoded content (same representation as unprotected binaries), so that
// GetContentBytes works transparently.
// Protected meta binaries consume the inner stream cipher in XML document
// order before any entry value does (Meta precedes Root), therefore this must
// be called before UnlockProtectedGroups to keep the cipher stream aligned.
func (cs *StreamManager) unlockProtectedBinaries(bs Binaries) error {
	for i := range bs {
		if !bs[i].isStreamProtected() {
			continue
		}

		content := string(bs[i].Content)

		// The stream cipher is consumed based on the length of the decoded
		// content, so content which is not valid base64 has to be rejected
		// instead of shifting every protected value after it
		if _, err := base64.StdEncoding.DecodeString(content); err != nil {
			return fmt.Errorf("%w (ID %d)", ErrInvalidProtectedBinary, bs[i].ID)
		}

		data := cs.Unpack(content)
		bs[i].Content = []byte(base64.StdEncoding.EncodeToString(data))
	}

	return nil
}

// lockProtectedBinaries locks the unlocked stream-protected binaries of a
// KDBX v3.1 metadata section, replacing the plain base64 encoded content with
// stream-encrypted content.
// Must be called before LockProtectedGroups to keep the cipher stream aligned
// with the XML document order (Meta precedes Root).
func (cs *StreamManager) lockProtectedBinaries(bs Binaries) error {
	for i := range bs {
		if !bs[i].isStreamProtected() {
			continue
		}

		data, err := base64.StdEncoding.DecodeString(string(bs[i].Content))
		if err != nil {
			return fmt.Errorf("%w (ID %d)", ErrInvalidProtectedBinary, bs[i].ID)
		}

		bs[i].Content = []byte(cs.Pack(data))
	}

	return nil
}

// ErrUnsupportedEncrypterType is retured if no encrypter manager can be created
// due to an invalid length of EncryptionIV
var ErrUnsupportedEncrypterType = errors.New("Type of encrypter unsupported")

// ErrUnsupportedStreamType is retured if no stream manager can be created
// due to an unsupported InnerRandomStreamID value
var ErrUnsupportedStreamType = errors.New("Type of stream manager unsupported")

// ErrInvalidProtectedBinary is retured if the content of a stream protected
// binary is not valid base64.
// Such content can neither be locked nor unlocked, since the amount of bytes
// taken from the inner stream cipher depends on it, and processing it anyway
// would corrupt every protected value which follows it.
var ErrInvalidProtectedBinary = errors.New(
	"gokeepasslib: content of a protected binary is not valid base64",
)
