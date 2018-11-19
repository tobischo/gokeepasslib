package crypto

type InsecureManager struct{}

func NewInsecureManager() *InsecureManager {
	return new(InsecureManager)
}

func (c *InsecureManager) Unpack(payload string) []byte {
	return []byte(payload)
}

func (c *InsecureManager) Pack(payload []byte) string {
	return string(payload)
}
