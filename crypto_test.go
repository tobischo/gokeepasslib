package gokeepasslib

import (
	"encoding/xml"
	"maps"
	"strings"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

const testMessage = "test message"

func TestInsecure(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte(testMessage)

	// Encrypt
	c, _ := NewStreamManager(NoStreamID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(NoStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != testMessage {
		t.Fatalf("Failed to decode insecure: should be 'test message' not '%s'", decrypted)
	}
}

func TestChaCha(t *testing.T) {
	key := make([]byte, 64)
	payload := []byte(testMessage)

	// Encrypt
	c, err := NewStreamManager(ChaChaStreamID, key)
	if err != nil {
		t.Fatalf("Failed to create stream manager: %v", err)
	}
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(ChaChaStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode chacha: should be 'test message' not '%s'", decrypted)
	}
}

func TestSalsa(t *testing.T) {
	key := make([]byte, 32)
	payload := []byte("test message")

	// Encrypt
	c, _ := NewStreamManager(SalsaStreamID, key)
	crypted := c.Pack(payload)

	// Decrypt
	c2, _ := NewStreamManager(SalsaStreamID, key)
	decrypted := c2.Unpack(crypted)

	if string(decrypted) != "test message" {
		t.Fatalf("Failed to decode salsa: should be 'test message' not '%s'", decrypted)
	}
}

// protectedEntryXML returns an entry with a title and a protected password
func protectedEntryXML(title, password string, children ...string) string {
	return "<Entry><String><Key>Title</Key><Value>" + title + "</Value></String>" +
		strings.Join(children, "") +
		"<String><Key>Password</Key><Value Protected=\"True\">" + password + "</Value></String>" +
		"</Entry>"
}

// collectPasswords collects the passwords of all entries of a group by their path
func collectPasswords(prefix string, g *Group, passwords map[string]string) {
	for _, e := range g.Entries {
		passwords[prefix+e.GetTitle()] = e.GetPassword()
		for _, h := range e.Histories {
			for _, he := range h.Entries {
				passwords[prefix+e.GetTitle()+"/History/"+he.GetTitle()] = he.GetPassword()
			}
		}
	}
	for i := range g.Groups {
		collectPasswords(prefix+g.Groups[i].Name+"/", &g.Groups[i], passwords)
	}
}

func TestUnlockProtectedGroupDocumentOrder(t *testing.T) {
	cases := []struct {
		title string
		// passwords are protected in this order, which is the document order
		passwords []string
		xmlData   func(p []string) string
		modify    func(g *Group, p []string)
		expected  map[string]string
	}{
		{
			title:     "entries before groups",
			passwords: []string{"password-a", "password-b"},
			xmlData: func(p []string) string {
				return "<Group>" + protectedEntryXML("A", p[0]) +
					"<Group><Name>G</Name>" + protectedEntryXML("B", p[1]) + "</Group></Group>"
			},
			expected: map[string]string{"A": "password-a", "G/B": "password-b"},
		},
		{
			title:     "groups before entries",
			passwords: []string{"password-b", "password-a"},
			xmlData: func(p []string) string {
				return "<Group><Group><Name>G</Name>" + protectedEntryXML("B", p[0]) + "</Group>" +
					protectedEntryXML("A", p[1]) + "</Group>"
			},
			expected: map[string]string{"A": "password-a", "G/B": "password-b"},
		},
		{
			title:     "entries and groups interleaved",
			passwords: []string{"password-a", "password-b", "password-c"},
			xmlData: func(p []string) string {
				return "<Group>" + protectedEntryXML("A", p[0]) +
					"<Group><Name>G</Name>" + protectedEntryXML("B", p[1]) + "</Group>" +
					protectedEntryXML("C", p[2]) + "</Group>"
			},
			expected: map[string]string{"A": "password-a", "C": "password-c", "G/B": "password-b"},
		},
		{
			title:     "value after the history",
			passwords: []string{"password-old", "password-new"},
			xmlData: func(p []string) string {
				return "<Group>" +
					protectedEntryXML("E", p[1], "<History>"+protectedEntryXML("E", p[0])+"</History>") +
					"</Group>"
			},
			expected: map[string]string{"E": "password-new", "E/History/E": "password-old"},
		},
		{
			title:     "children added after unmarshalling",
			passwords: []string{"password-b", "password-a", "password-c", "password-d"},
			xmlData: func(p []string) string {
				return "<Group><Group><Name>G</Name>" + protectedEntryXML("B", p[0]) + "</Group>" +
					protectedEntryXML("A", p[1]) + "</Group>"
			},
			modify: func(g *Group, p []string) {
				entry := NewEntry()
				entry.Values = []ValueData{
					{Key: "Title", Value: V{Content: "C"}},
					{Key: "Password", Value: V{Content: p[2], Protected: w.NewBoolWrapper(true)}},
				}
				g.Entries = append(g.Entries, entry)

				group := NewGroup()
				group.Name = "H"
				entry = entry.Clone()
				entry.Values[0].Value.Content = "D"
				entry.Values[1].Value.Content = p[3]
				group.Entries = []Entry{entry}
				g.Groups = append(g.Groups, group)
			},
			expected: map[string]string{
				"A":   "password-a",
				"C":   "password-c",
				"G/B": "password-b",
				"H/D": "password-d",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			key := make([]byte, 64)

			lockManager, err := NewStreamManager(ChaChaStreamID, key)
			if err != nil {
				t.Fatalf("Failed to create stream manager: %v", err)
			}
			packed := make([]string, len(c.passwords))
			for i, password := range c.passwords {
				packed[i] = lockManager.Pack([]byte(password))
			}

			var group Group
			if err := xml.Unmarshal([]byte(c.xmlData(packed)), &group); err != nil {
				t.Fatalf("Failed to unmarshal group: %v", err)
			}
			if c.modify != nil {
				c.modify(&group, packed)
			}

			unlockManager, err := NewStreamManager(ChaChaStreamID, key)
			if err != nil {
				t.Fatalf("Failed to create stream manager: %v", err)
			}
			unlockManager.UnlockProtectedGroup(&group)

			passwords := map[string]string{}
			collectPasswords("", &group, passwords)
			if !maps.Equal(passwords, c.expected) {
				t.Fatalf("Received passwords %q, expected %q", passwords, c.expected)
			}
		})
	}
}
