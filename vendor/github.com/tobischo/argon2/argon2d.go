// Copyright 2024 Tobias Schoknecht. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 implements the key derivation function Argon2.
// Argon2 was selected as the winner of the Password Hashing Competition and can
// be used to derive cryptographic keys from passwords.
//
// For a detailed specification of Argon2 see [1].
//
// If you aren't sure which function you need, use Argon2id (IDKey) and
// the parameter recommendations for your scenario.
//
// # Argon2d
//
// Argon2d (implemented by DKey) is a version that is not side channel resistent
// but provideds maximum security for brute force attacks.
// This is not exposed by golang.org/x/crypto/argon2.
// It is in a separate file to avoid conflicts when updating the remaining code.
//
// [1] https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
// [2] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.3
package argon2

// DKey derives a key from the password, salt, and cost parameters using
// Argon2d returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//  key := argon2.DKey([]byte("some password"), salt, 1, 64*1024, 4, 32)
//
// The draft RFC recommends[2] time=3, and memory=32*1024 is a sensible number.
// If using that amount of memory (32 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=32*1024 sets the memory cost to ~32 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func DKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
  return deriveKey(argon2d, password, salt, nil, nil, time, memory, threads, keyLen)
}
