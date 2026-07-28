package gokeepasslib

import (
	"bytes"
	"errors"
	"testing"

	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

const (
	testTag                  = "tag"
	testSubGroupTags         = "subgrouptag"
	testCustomDataKey        = "gokeepasslib_test"
	testGroupCustomDataValue = "group custom data"
)

var (
	testCustomIconUUID = UUID{
		0xde, 0xad, 0xbe, 0xef,
		0xc0, 0xff, 0xee, 0xde,
		0xed, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd,
	}

	testPreviousParentGroupUUID = UUID{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
	}
)

func TestFormatVersion(t *testing.T) {
	cases := []struct {
		title           string
		majorVersion    uint16
		minorVersion    uint16
		expectedVersion formatVersion
		expectedString  string
		expectedKdbx4   bool
		expectedKdbx41  bool
	}{
		{
			title:           "KDBX 3.1",
			majorVersion:    3,
			minorVersion:    1,
			expectedVersion: formatVersion31,
			expectedString:  "3.1",
		},
		{
			title:           "KDBX 4.0",
			majorVersion:    4,
			minorVersion:    0,
			expectedVersion: formatVersion40,
			expectedString:  "4.0",
			expectedKdbx4:   true,
		},
		{
			title:           "KDBX 4.1",
			majorVersion:    4,
			minorVersion:    1,
			expectedVersion: formatVersion41,
			expectedString:  "4.1",
			expectedKdbx4:   true,
			expectedKdbx41:  true,
		},
		{
			// A minor version above the highest known one is still readable,
			// since minor versions do not change the binary file format
			title:           "KDBX 4.2",
			majorVersion:    4,
			minorVersion:    2,
			expectedVersion: 4<<16 | 2,
			expectedString:  "4.2",
			expectedKdbx4:   true,
			expectedKdbx41:  true,
		},
		{
			// A high minor version must not be mistaken for a higher major version
			title:           "KDBX 3.10",
			majorVersion:    3,
			minorVersion:    10,
			expectedVersion: 3<<16 | 10,
			expectedString:  "3.10",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			header := &DBHeader{
				Signature: &Signature{
					BaseSignature:      BaseSignature,
					SecondarySignature: SecondarySignature,
					MajorVersion:       c.majorVersion,
					MinorVersion:       c.minorVersion,
				},
			}

			version := header.formatVersion()
			if version != c.expectedVersion {
				t.Errorf("Expected version %d, received %d", c.expectedVersion, version)
			}

			if version.String() != c.expectedString {
				t.Errorf(
					"Expected version '%s', received '%s'",
					c.expectedString,
					version.String(),
				)
			}

			if header.IsKdbx4() != c.expectedKdbx4 {
				t.Errorf("Expected IsKdbx4 to be %v", c.expectedKdbx4)
			}

			if header.IsKdbx41() != c.expectedKdbx41 {
				t.Errorf("Expected IsKdbx41 to be %v", c.expectedKdbx41)
			}
		})
	}
}

// databaseWithAllElements builds a database which makes use of every element
// that is supported for its file format version
func databaseWithAllElements(t *testing.T, options ...DatabaseOption) *Database {
	t.Helper()

	db := NewDatabase(options...)
	db.Credentials = NewPasswordCredentials(password)

	formatted := !db.Header.IsKdbx4()
	now := w.Now(w.WithFormatted(formatted))

	db.Content.Meta.DatabaseName = "All elements"
	db.Content.Meta.DatabaseDescription = "Database covering all supported elements"
	db.Content.Meta.Color = "#FFFF00"
	db.Content.Meta.RecycleBinEnabled = w.NewBoolWrapper(true)
	db.Content.Meta.CustomIcons = []CustomIcon{
		{
			UUID: testCustomIconUUID,
			Data: encodedIcon,
		},
	}
	db.Content.Meta.CustomData = []CustomData{
		{
			Key:   testCustomDataKey,
			Value: "meta custom data",
		},
	}

	binary := db.AddBinary([]byte("example binary content"))

	group := &db.Content.Root.Groups[0]
	group.Name = "All elements"
	group.Notes = "Group notes"
	group.CustomIconUUID = testCustomIconUUID

	subGroup := NewGroup(WithGroupFormattedTime(formatted))
	subGroup.Name = "Subgroup"
	group.Groups = append(group.Groups, subGroup)

	entry := NewEntry(WithEntryFormattedTime(formatted))
	entry.Values = append(
		entry.Values,
		ValueData{Key: "Title", Value: V{Content: "Entry title"}},
		ValueData{
			Key:   "Password",
			Value: V{Content: password, Protected: w.NewBoolWrapper(true)},
		},
	)
	entry.CustomIconUUID = testCustomIconUUID
	entry.ForegroundColor = "#FF0000"
	entry.BackgroundColor = "#00FF00"
	entry.OverrideURL = "https://example.com"
	entry.Tags = "tag1;tag2"
	entry.Binaries = append(entry.Binaries, binary.CreateReference("example.txt"))
	entry.AutoType = AutoTypeData{
		Enabled:         w.NewBoolWrapper(true),
		DefaultSequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}",
		Associations: []AutoTypeAssociation{
			{Window: "Target Window", KeystrokeSequence: "{USERNAME}{TAB}{PASSWORD}"},
		},
	}
	entry.CustomData = []CustomData{
		{
			Key:   testCustomDataKey,
			Value: "entry custom data",
		},
	}

	historyEntry := entry.Clone()
	historyEntry.UUID = entry.UUID
	historyEntry.Histories = nil
	entry.Histories = []History{{Entries: []Entry{historyEntry}}}

	// Replace the sample entry which NewDatabase creates
	group.Entries = []Entry{entry}

	db.Content.Root.DeletedObjects = []DeletedObjectData{
		{
			UUID:         NewUUID(),
			DeletionTime: &now,
		},
	}

	if db.Header.IsKdbx41() {
		addKdbx41Elements(db, now)
	}

	return db
}

// addKdbx41Elements sets every element which was introduced in KDBX 4.1
func addKdbx41Elements(db *Database, now w.TimeWrapper) {
	lastModificationTime := now

	db.Content.Meta.CustomIcons[0].Name = "Custom icon name"
	db.Content.Meta.CustomIcons[0].LastModificationTime = &lastModificationTime
	db.Content.Meta.CustomData[0].LastModificationTime = &lastModificationTime

	group := &db.Content.Root.Groups[0]
	group.Tags = "grouptag1;grouptag2"
	group.PreviousParentGroup = &testPreviousParentGroupUUID
	group.CustomData = []CustomData{
		{
			Key:   testCustomDataKey,
			Value: testGroupCustomDataValue,
		},
	}

	group.Groups[0].Tags = testSubGroupTags
	group.Groups[0].PreviousParentGroup = &testPreviousParentGroupUUID

	qualityCheck := w.NewBoolWrapper(false)
	group.Entries[0].QualityCheck = &qualityCheck
	group.Entries[0].PreviousParentGroup = &testPreviousParentGroupUUID
}

// TestKDBX41RoundTrip ensures that all elements which were introduced in
// KDBX 4.1 survive encoding and decoding a database
func TestKDBX41RoundTrip(t *testing.T) {
	db := databaseWithAllElements(t, WithDatabaseKDBXVersion41())

	// The encoder expects the protected values of the database to be locked
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("Failed to lock protected entries: %s", err)
	}

	var buffer bytes.Buffer
	if err := NewEncoder(&buffer).Encode(db); err != nil {
		t.Fatalf("Failed to encode database: %s", err)
	}

	decoded := NewDatabase()
	decoded.Credentials = NewPasswordCredentials(password)
	if err := NewDecoder(&buffer).Decode(decoded); err != nil {
		t.Fatalf("Failed to decode database: %s", err)
	}

	if err := decoded.UnlockProtectedEntries(); err != nil {
		t.Fatalf("Failed to unlock protected entries: %s", err)
	}

	decodedEntry := decoded.Content.Root.Groups[0].Entries[0]
	if pw := decodedEntry.GetPassword(); pw != password {
		t.Errorf("Failed to decode the password, received '%s'", pw)
	}

	// The protected values are packed into a single stream, so a history entry
	// only decodes correctly if the order of the elements is kept
	if len(decodedEntry.Histories) != 1 || len(decodedEntry.Histories[0].Entries) != 1 {
		t.Fatalf("Expected 1 history entry, received %+v", decodedEntry.Histories)
	}

	if pw := decodedEntry.Histories[0].Entries[0].GetPassword(); pw != password {
		t.Errorf("Failed to decode the password of the history entry, received '%s'", pw)
	}

	if !decoded.Header.IsKdbx41() {
		t.Fatalf(
			"Expected a KDBX 4.1 file, received version %d.%d",
			decoded.Header.Signature.MajorVersion,
			decoded.Header.Signature.MinorVersion,
		)
	}

	meta := decoded.Content.Meta
	if len(meta.CustomIcons) != 1 {
		t.Fatalf("Expected 1 custom icon, received %d", len(meta.CustomIcons))
	}

	if meta.CustomIcons[0].Name != "Custom icon name" {
		t.Errorf(
			"Failed to decode CustomIcon.Name, received '%s'",
			meta.CustomIcons[0].Name,
		)
	}

	if meta.CustomIcons[0].LastModificationTime == nil {
		t.Errorf("Failed to decode CustomIcon.LastModificationTime")
	}

	if len(meta.CustomData) != 1 || meta.CustomData[0].LastModificationTime == nil {
		t.Errorf("Failed to decode the LastModificationTime of the meta custom data")
	}

	group := decoded.Content.Root.Groups[0]
	if group.Tags != "grouptag1;grouptag2" {
		t.Errorf("Failed to decode Group.Tags, received '%s'", group.Tags)
	}

	if group.PreviousParentGroup == nil {
		t.Errorf("Failed to decode Group.PreviousParentGroup")
	} else if !group.PreviousParentGroup.Compare(testPreviousParentGroupUUID) {
		t.Errorf(
			"Failed to decode Group.PreviousParentGroup, received %x",
			*group.PreviousParentGroup,
		)
	}

	if len(group.CustomData) != 1 || group.CustomData[0].Value != testGroupCustomDataValue {
		t.Errorf("Failed to decode Group.CustomData, received %+v", group.CustomData)
	}

	if len(group.Groups) != 1 {
		t.Fatalf("Expected 1 subgroup, received %d", len(group.Groups))
	}

	if group.Groups[0].Tags != testSubGroupTags {
		t.Errorf(
			"Failed to decode Tags of the subgroup, received '%s'",
			group.Groups[0].Tags,
		)
	}

	if group.Groups[0].PreviousParentGroup == nil {
		t.Errorf("Failed to decode PreviousParentGroup of the subgroup")
	}

	if len(group.Entries) != 1 {
		t.Fatalf("Expected 1 entry, received %d", len(group.Entries))
	}

	entry := group.Entries[0]
	if entry.QualityCheck == nil {
		t.Errorf("Failed to decode Entry.QualityCheck")
	} else if entry.QualityCheck.Bool {
		t.Errorf("Failed to decode Entry.QualityCheck, expected it to be false")
	}

	if entry.PreviousParentGroup == nil {
		t.Errorf("Failed to decode Entry.PreviousParentGroup")
	} else if !entry.PreviousParentGroup.Compare(testPreviousParentGroupUUID) {
		t.Errorf(
			"Failed to decode Entry.PreviousParentGroup, received %x",
			*entry.PreviousParentGroup,
		)
	}
}

// TestDecodeKDBX41File ensures that the elements which were introduced in
// KDBX 4.1 are read from a KDBX 4.1 file.
//
// tests/kdbx41/example.kdbx was created out of the KeePass generated
// tests/kdbx4/example.kdbx by adding every element of KDBX 4.1 to it.
func TestDecodeKDBX41File(t *testing.T) {
	db := decodeDatabase(t, "tests/kdbx41/example.kdbx", examplePassword)

	if !db.Header.IsKdbx41() {
		t.Fatalf(
			"Expected a KDBX 4.1 file, received version %d.%d",
			db.Header.Signature.MajorVersion,
			db.Header.Signature.MinorVersion,
		)
	}

	meta := db.Content.Meta
	if len(meta.CustomIcons) != 1 {
		t.Fatalf("Expected 1 custom icon, received %d", len(meta.CustomIcons))
	}

	if meta.CustomIcons[0].Name != "Named custom icon" {
		t.Errorf(
			"Failed to decode CustomIcon.Name, received '%s'",
			meta.CustomIcons[0].Name,
		)
	}

	if meta.CustomIcons[0].LastModificationTime == nil {
		t.Errorf("Failed to decode CustomIcon.LastModificationTime")
	} else if meta.CustomIcons[0].LastModificationTime.Formatted {
		t.Errorf("Expected CustomIcon.LastModificationTime to use the KDBX 4 format")
	}

	if len(meta.CustomData) != 1 {
		t.Fatalf("Expected 1 meta custom data item, received %d", len(meta.CustomData))
	}

	if meta.CustomData[0].LastModificationTime == nil {
		t.Errorf("Failed to decode the LastModificationTime of the meta custom data")
	}

	group := db.Content.Root.Groups[0]
	if group.Tags != "roottag1;roottag2" {
		t.Errorf("Failed to decode Group.Tags, received '%s'", group.Tags)
	}

	if len(group.CustomData) != 1 || group.CustomData[0].Value != testGroupCustomDataValue {
		t.Errorf("Failed to decode Group.CustomData, received %+v", group.CustomData)
	}

	subGroup := group.Groups[1]
	if subGroup.Tags != testSubGroupTags {
		t.Errorf("Failed to decode Tags of the subgroup, received '%s'", subGroup.Tags)
	}

	if subGroup.PreviousParentGroup == nil {
		t.Fatalf("Failed to decode PreviousParentGroup of the subgroup")
	}

	if !subGroup.PreviousParentGroup.Compare(group.UUID) {
		t.Errorf(
			"Failed to decode PreviousParentGroup of the subgroup, received %x",
			*subGroup.PreviousParentGroup,
		)
	}

	entry := subGroup.Entries[0]
	if entry.QualityCheck == nil {
		t.Fatalf("Failed to decode Entry.QualityCheck")
	}

	if entry.QualityCheck.Bool {
		t.Errorf("Failed to decode Entry.QualityCheck, expected it to be false")
	}

	if entry.PreviousParentGroup == nil {
		t.Fatalf("Failed to decode Entry.PreviousParentGroup")
	}

	if !entry.PreviousParentGroup.Compare(group.UUID) {
		t.Errorf(
			"Failed to decode Entry.PreviousParentGroup, received %x",
			*entry.PreviousParentGroup,
		)
	}
}

// TestEnsureRequiredKdbxFormatVersion covers the file format version which is
// selected when encoding a database
func TestEnsureRequiredKdbxFormatVersion(t *testing.T) {
	cases := []struct {
		title           string
		options         []DatabaseOption
		modify          func(db *Database)
		expectedVersion formatVersion
		expectedField   string
	}{
		{
			title:           "KDBX 3.1 without KDBX 4.1 elements",
			options:         []DatabaseOption{WithDatabaseKDBXVersion3()},
			expectedVersion: formatVersion31,
		},
		{
			title:           "KDBX 4.0 without KDBX 4.1 elements",
			options:         []DatabaseOption{WithDatabaseKDBXVersion40()},
			expectedVersion: formatVersion40,
		},
		{
			title:           "KDBX 4.1 without KDBX 4.1 elements",
			options:         []DatabaseOption{WithDatabaseKDBXVersion41()},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 4.0 with group tags is upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion40()},
			modify: func(db *Database) {
				db.Content.Root.Groups[0].Tags = testTag
			},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 4.0 with a previous parent group is upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion40()},
			modify: func(db *Database) {
				db.Content.Root.Groups[0].Entries[0].PreviousParentGroup = &testPreviousParentGroupUUID
			},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 4.0 with a quality check is upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion40()},
			modify: func(db *Database) {
				qualityCheck := w.NewBoolWrapper(false)
				db.Content.Root.Groups[0].Entries[0].QualityCheck = &qualityCheck
			},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 4.0 with a named custom icon is upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion40()},
			modify: func(db *Database) {
				db.Content.Meta.CustomIcons = []CustomIcon{
					{UUID: testCustomIconUUID, Data: encodedIcon, Name: "Name"},
				}
			},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 4.0 with a modified custom data item is upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion40()},
			modify: func(db *Database) {
				now := w.Now(w.WithKDBX4Formatting)
				db.Content.Meta.CustomData = []CustomData{
					{Key: "key", Value: "value", LastModificationTime: &now},
				}
			},
			expectedVersion: formatVersion41,
		},
		{
			title:   "KDBX 3.1 with group tags can not be upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion3()},
			modify: func(db *Database) {
				db.Content.Root.Groups[0].Tags = testTag
			},
			expectedVersion: formatVersion31,
			expectedField:   "Group.Tags",
		},
		{
			title:   "KDBX 3.1 with a quality check can not be upgraded",
			options: []DatabaseOption{WithDatabaseKDBXVersion3()},
			modify: func(db *Database) {
				qualityCheck := w.NewBoolWrapper(false)
				db.Content.Root.Groups[0].Entries[0].QualityCheck = &qualityCheck
			},
			expectedVersion: formatVersion31,
			expectedField:   "Entry.QualityCheck",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			db := NewDatabase(c.options...)
			db.Credentials = NewPasswordCredentials(password)

			if c.modify != nil {
				c.modify(db)
			}

			err := db.ensureRequiredKdbxFormatVersion()

			var upgradeErr ErrKdbxVersionUpgradeRequired
			switch {
			case c.expectedField == "" && err != nil:
				t.Fatalf("Received unexpected error: %s", err)
			case c.expectedField != "" && !errors.As(err, &upgradeErr):
				t.Fatalf("Expected an ErrKdbxVersionUpgradeRequired, received %v", err)
			case c.expectedField != "" && upgradeErr.Field != c.expectedField:
				t.Errorf(
					"Expected the error to name '%s', received '%s'",
					c.expectedField,
					upgradeErr.Field,
				)
			}

			if version := db.Header.formatVersion(); version != c.expectedVersion {
				t.Errorf(
					"Expected file format version %s, received %s",
					c.expectedVersion,
					version,
				)
			}
		})
	}
}

// TestEnsureRequiredKdbxFormatVersionKeepsDefaultSignatures ensures that
// upgrading the file format version of a database does not change the package
// level default signatures
func TestEnsureRequiredKdbxFormatVersionKeepsDefaultSignatures(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion40())
	db.Content.Root.Groups[0].Tags = testTag

	if err := db.ensureRequiredKdbxFormatVersion(); err != nil {
		t.Fatalf("Received unexpected error: %s", err)
	}

	if DefaultKDBX40Sig.MinorVersion != 0 {
		t.Errorf(
			"DefaultKDBX40Sig was modified, minor version is %d",
			DefaultKDBX40Sig.MinorVersion,
		)
	}
}
