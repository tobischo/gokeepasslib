package crypto

// InsecureManager is a fake cipher that implements CryptoStream interface
type InsecureManager struct{}

// NewInsecureManager initialize a new InsecureManager interfaced with CryptoStream
func NewInsecureManager() *InsecureManager {
	return new(InsecureManager)
}

func (c *InsecureManager) Unpack(payload string) []byte {
	return []byte(payload)
}

func (c *InsecureManager) Pack(payload []byte) string {
	return string(payload)
}
