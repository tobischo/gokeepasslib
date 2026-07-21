### TO BE RELEASED

* Add support for stream-protected binaries in the KDBX v3.1 metadata section (`<Binary Protected="True">`), matching the KeePass 2 reference implementation; previously the inner stream cipher was not advanced for them, corrupting every subsequent protected value on decode
* Return the actual decoded length from `Binary.GetContentBytes` for uncompressed base64 content instead of a zero-padded buffer
* Propagate group child unmarshalling errors instead of silently dropping the child element, which desynced the protection stream and corrupted all subsequent protected values
* Add support for the KDBX 4.1 file format
    - Adds `WithDatabaseKDBXVersion41()`, `NewKDBX41Header()`, `DefaultKDBX41Sig`
      and `(*DBHeader).IsKdbx41()`
    - Adds `Tags`, `PreviousParentGroup` and `CustomData` to `Group`
    - Adds `QualityCheck` and `PreviousParentGroup` to `Entry`
    - Adds `Name` and `LastModificationTime` to `CustomIcon`
    - Adds `LastModificationTime` to `CustomData`
    - A KDBX 4.0 database is upgraded to KDBX 4.1 while encoding if it contains
      elements which require it, following KeePass, which writes a database with
      the lowest file format version that is able to hold its content.
      Encoding a KDBX 3.1 database containing such elements returns an
      `ErrKdbxVersionUpgradeRequired` instead of dropping them silently, since
      upgrading it would change the structure of the file itself
* Deprecate `DefaultKDBX4Sig`, `NewKDBX4Header()` and `WithDatabaseKDBXVersion4()` in
  favour of the same names with a `40` version suffix, which distinguishes them from
  their KDBX 4.1 counterparts.
  `NewKDBX4FileHeaders()` keeps its name, as the file headers depend on the major
  version only
* Correct the XML written by the encoder to match the KDBX XML schema
    - The `Binary` and `CustomData` elements of an entry are written in the
      documented order
    - `CustomIconUUID` is not written anymore if no custom icon is set
    - `EntryTemplatesGroup`, `LastSelectedGroup`, `LastTopVisibleGroup` and
      `LastTopVisibleEntry` are initialized with a zero UUID instead of an empty
      value, as those elements have to contain a UUID
    - Groups now contain an empty `CustomData` element if they have no custom
      data, matching the existing behaviour for entries
* Add `(UUID).IsZero()` and the `ZeroUUIDText` constant
* Marshal `BoolWrapper` and `NullableBoolWrapper` through value receivers, so that
  they are also written as `True`/`False`/`null` when a struct containing them is
  marshalled by value instead of through a pointer

### v3.6.2

* Adapt `composeContentBlocks31` method to fix file size inflation on encoding for KDBX v3.1 files

### v3.6.1

* Updated `golang.org/x/crypto`
* Bump CI go versions to 1.22 and 1.23 instead of 1.21 and 1.22

### v3.6.0

* Add golangci-lint to ci steps and correct some of the findings
* Add twofish support

### v3.5.3

* Use chacha20 from official implementation
* Updated `golang.org/x/crypto`
* Replaced `github.com/aead/argon2` with `github.com/tobischo/argon2`

### v3.5.2

* Setup dependabot
* Bump dependencies

### v3.5.1

* Update `golang.org/x/crypto` to `v0.8.0`
* Update `golang.org/x/sys` to `v0.7.0`

### v3.5.0

* Add support for Cloning `Group` and `Entry`

### v3.4.1

* Fix key file support to actually deal with the different supported key file types

### v3.4.0

* Fix binary referencing after remove
* Add binary garbage collections if all references have been removed

### v3.3.0

* Add database `AddBinary` and `FindBinary` functions

### v3.2.5

* Add missing CustomData support for entries

### v3.2.4

* Add support for handling protected value unlocking with `Entry` or `Group` being loaded first from XML
* Initialize fresh UUIDs on unmarshal in case they are missing

### v3.2.3

* Adds `(*Binary).GetContentString() (string, error)` and `(*Binary).GetContentBytes() ([]byte, error)` funcs
* Deprecates `(*Binary).GetContent() (string, error)`
* Also adds `CustomIcon` support on `Group` level

### v3.2.2

* Correctly support multiple Window Associations in an entry's AutoType data

### v3.2.1

* Add missing DefaultSequence in AutoType data

### v3.2.0

* Add support for custom icons

### v3.1.0

* Add initialization support for KDBXv4 files
* Add SettingsChanged MetaData field

### v3.0.5

* Improve time marshalling/unmarshalling performance

### v3.0.4

* Ensure time values are formatted according to the version when encoding the DB to file
* Split up code into several smaller files

### v3.0.3

* Split up `BoolWrapper` and `NullableBoolWrapper`

### v3.0.2

* Improve AES decrypt performance (cont.)

### v3.0.1

* Improve AES decrypt performance

### v3.0.0

* Fix `BoolWrapper` to support null values
    - This introduced a breaking change

### v2.1.3

* Fix `TimeWrapper` marshalling and unmarshalling

### v2.1.2

* Attempt to fix `TimeWrapper`

### v2.1.1

* Add `ParseKeyData` to allow loading keys without file operation

### v2.1.0

* Add functional option support for all kinds of initializers

### v2.0.3

* Add KDBX4 HMAC verification on file decoding

### v2.0.2

* Fix KDBX4 HMAC building for encrypted content blocks on file encoding

### v2.0.1

* Drop counter for SalsaStream

### v2.0.0

* KDBX v4.0 support
* Argon2 support
* ChaCha20 support
* Restructured code
* Fixed support for keyfile
* Moved type wrappers into separate package

### v1.0.0

* KDBX v3.1 support
