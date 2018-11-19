gokeepasslib (unstable)
============

[![Travis Build state](https://api.travis-ci.org/tobischo/gokeepasslib.svg)](https://travis-ci.org/tobischo/gokeepasslib)

gokeepasslib is a library which allows reading Keepass 2 files (kdbx).

# This is a temporary fork!
This is a fork developed by AlessioDP to work on KDBX v4 support.

**This fork is UNSTABLE.**

### Main changes
* Restructured code
* Argon2 support
* ChaCha20 support
* Added support for keyfile (it was broken)
* New tests
* Find of binaries based on Database instead of Binaries (due to difference between KDBX 3.1 and 4.0)
* Main methods, used by other developers, should stay into gokeepasslib package
