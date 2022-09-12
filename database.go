package gokeepasslib

import (
	"errors"
	"fmt"
)

// ErrInvalidDatabaseOrCredentials is returned when the file cannot be read properly.
var ErrInvalidDatabaseOrCredentials = errors.New(
	"Cannot read database: Either credentials are invalid or the database file is corrupted",
)

// Database stores all contents necessary for a keepass database file
type Database struct {
	Options     *DBOptions
	Credentials *DBCredentials
	Header      *DBHeader
	Hashes      *DBHashes
	Content     *DBContent
}

// DBOptions stores options for database decoding/encoding
type DBOptions struct {
	ValidateHashes bool // True to validate header hash
}

type DatabaseOption func(*Database)

func WithDatabaseFormattedTime(formatted bool) DatabaseOption {
	return func(db *Database) {
		WithDBContentFormattedTime(formatted)(db.Content)
	}
}

func WithDatabaseKDBXVersion3() DatabaseOption {
	return func(db *Database) {
		db.Header = NewKDBX3Header()
	}
}

func WithDatabaseKDBXVersion4() DatabaseOption {
	return func(db *Database) {
		db.Header = NewKDBX4Header()
		withDBContentKDBX4InnerHeader(db.Content)
	}
}

// NewDatabase creates a new database with some sensable default settings in KDBX version 3.1.
// To create a database with no settings pre-set, use gokeepasslib.Database{}
func NewDatabase(options ...DatabaseOption) *Database {
	db := &Database{
		Options:     NewOptions(),
		Credentials: new(DBCredentials),
		Content:     NewContent(),
	}

	for _, option := range options {
		option(db)
	}

	if db.Header == nil {
		db.Header = NewHeader()
	}

	if db.Hashes == nil {
		db.Hashes = NewHashes(db.Header)
	}

	return db
}

// NewOptions creates new options with default values
func NewOptions() *DBOptions {
	return &DBOptions{
		ValidateHashes: true,
	}
}

func (db *Database) ensureKdbxFormatVersion() {
	db.Content.setKdbxFormatVersion(
		db.Header.formatVersion(),
	)
}

// getTransformedKey returns the transformed key Credentials
func (db *Database) getTransformedKey() ([]byte, error) {
	if db.Credentials == nil {
		return nil, ErrRequiredAttributeMissing("Credentials")
	}
	return db.Credentials.buildTransformedKey(db)
}

// GetEncrypterManager returns an EncryptManager based on the master key and EncryptionIV, or nil if the type is unsupported
func (db *Database) GetEncrypterManager(transformedKey []byte) (*EncrypterManager, error) {
	return NewEncrypterManager(
		buildMasterKey(db, transformedKey),
		db.Header.FileHeaders.EncryptionIV,
	)
}

// GetStreamManager returns a StreamManager based on the db headers, or nil if the type is unsupported
// Can be used to lock only certain entries instead of calling
func (db *Database) GetStreamManager() (*StreamManager, error) {
	if db.Header != nil && db.Header.Signature != nil {
		if db.Header.IsKdbx4() {
			if db.Content == nil ||
				db.Content.InnerHeader == nil ||
				db.Content.InnerHeader.InnerRandomStreamKey == nil {
				return nil, ErrInvalidDatabaseOrCredentials
			}

			return NewStreamManager(
				db.Content.InnerHeader.InnerRandomStreamID,
				db.Content.InnerHeader.InnerRandomStreamKey,
			)
		}

		if db.Header.FileHeaders != nil &&
			db.Header.FileHeaders.ProtectedStreamKey == nil {
			return nil, ErrInvalidDatabaseOrCredentials
		}

		return NewStreamManager(
			db.Header.FileHeaders.InnerRandomStreamID,
			db.Header.FileHeaders.ProtectedStreamKey,
		)
	}
	return nil, nil
}

// UnlockProtectedEntries goes through the entire database and encrypts
// any Values in entries with protected=true set.
// This should be called after decoding if you want to view plaintext password in an entry
// Warning: If you call this when entry values are already unlocked, it will cause them to be unreadable
func (db *Database) UnlockProtectedEntries() error {
	manager, err := db.GetStreamManager()
	if err != nil {
		return err
	}
	if manager == nil {
		return ErrUnsupportedStreamType
	}
	manager.UnlockProtectedGroups(db.Content.Root.Groups)
	return nil
}

// LockProtectedEntries goes through the entire database and decrypts
// any Values in entries with protected=true set.
// Warning: Do not call this if entries are already locked
// Warning: Encoding a database calls LockProtectedEntries automatically
func (db *Database) LockProtectedEntries() error {
	manager, err := db.GetStreamManager()
	if err != nil {
		return err
	}
	manager.LockProtectedGroups(db.Content.Root.Groups)
	return nil
}

// AddBinary adds a binary to the database.
// It takes care of adding it to the correct place based on the format version
func (db *Database) AddBinary(binaryContent []byte) *Binary {
	if db.Header.IsKdbx4() {
		return db.getBinaries().Add(binaryContent, WithKDBXv4Binary)
	}
	return db.getBinaries().Add(binaryContent, WithKDBXv31Binary)
}

// FindBinary returns the binary with the given id if one could be found. It returns nil otherwise
func (db *Database) FindBinary(id int) *Binary {
	return db.getBinaries().Find(id)
}

// ErrRequiredAttributeMissing is returned if a required value is not given
type ErrRequiredAttributeMissing string

func (e ErrRequiredAttributeMissing) Error() string {
	return fmt.Sprintf(
		"gokeepasslib: operation can not be performed if database does not have %s",
		string(e),
	)
}

type binariesUsages map[int][]*BinaryReference

func (db *Database) getBinaries() *Binaries {
	if db.Header.IsKdbx4() {
		return &db.Content.InnerHeader.Binaries
	}

	return &db.Content.Meta.Binaries
}

func (db *Database) cleanupBinaries() {
	usages := db.getBinariesUsages()
	updated := Binaries{}
	counter := 0

	for _, binary := range *db.getBinaries() {
		if refs, ok := usages[binary.ID]; ok {
			for _, ref := range refs {
				ref.Value.ID = counter
			}
			binary.ID = counter
			updated = append(updated, binary)
			counter++
		}
	}

	*db.getBinaries() = updated
}

func addEntriesBinaries(result binariesUsages, entries []Entry) {
	for _, entry := range entries {
		for i, binary := range entry.Binaries {
			id := binary.Value.ID
			result[id] = append(result[id], &entry.Binaries[i])
		}
		for _, history := range entry.Histories {
			addEntriesBinaries(result, history.Entries)
		}
	}
}

func addGroupBinaries(result binariesUsages, parent *Group) {
	addEntriesBinaries(result, parent.Entries)
	for _, group := range parent.Groups {
		addGroupBinaries(result, &group)
	}
}

func (db *Database) getBinariesUsages() binariesUsages {
	result := binariesUsages{}

	addGroupBinaries(result, &db.Content.Root.Groups[0])
	return result
}
