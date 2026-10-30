# AES-256 and AES-256-GCM

This addition provides portable, dependency-free C11 modules for libmtcrypto.
The only shared library helper is the existing secure_clear(). No OpenSSL,
external cryptographic library, dynamic allocation or OS interface is used.
Database handling, nonce generation and passphrase/key derivation are outside
these modules. Existing TOTP files and APIs are unchanged.

## Files and build

* include/aes_256.h and lib/aes_256.c: AES-256 key expansion, block encryption,
  block decryption and context erasure.
* include/aes_256_gcm.h and lib/aes_256_gcm.c: authenticated encryption and
  authenticated decryption with fixed 12-byte IVs and selectable 12- or 16-byte tags.
* tests/aes_256_test.c and tests/aes_256_gcm_test.c: standalone unit tests.

The patch adds the source files to lib/Makefile and both tests to the existing
unit_tests.sh. From the repository root:

    make -C lib CC=gcc
    cd tests
    bash unit_tests.sh

The CC override is optional if the Makefile's default clang is installed.
The added SOURCES += assignment does not remove locally added totp.c entries.

## Block API

All encrypt/decrypt functions return 1 on success, 0 for invalid arguments.
The block API operates on exactly 16 bytes with a 32-byte key. It is a block
primitive, not an application encryption mode; it does not add padding.

Use aes_256_init() to expand a key into a caller-owned aes_256_ctx_t, then
call aes_256_encrypt_block()/aes_256_decrypt_block(). Exact in-place operation
is supported. Initialise before use, do not modify the context concurrently,
and do not overlap its storage with key/input/output buffers. Call
 aes_256_clear() when finished; a cleared context is rejected by block calls.
The single-shot aes_256_encrypt()/aes_256_decrypt() functions expand and erase
a local context automatically. Keys and input/output buffers must provide the
fixed sizes specified in the header; C cannot discover allocated sizes.

The arithmetic S-box avoids secret-indexed lookup tables. GF arithmetic uses
fixed-size loops; branches depend on public round/exponent/mode values. This
is a deliberately small portable implementation rather than a high-throughput
AES-NI backend. No claim of compiler-independent constant-time behaviour,
physical side-channel resistance, independent audit or FIPS certification is
made. Published-vector testing is not CAVP validation.

## GCM profile and calling conventions

The API fixes the key/nonce sizes and accepts either standard tag size:

| Item | Bytes |
| --- | ---: |
| AES key | 32 |
| Nonce / IV | 12 |
| Authentication tag | 12 or 16, selected by `tag_length` |
| Ciphertext | Same length as plaintext |

Output comes first, followed by its capacity. Encryption receives a writable
tag buffer followed by tag_length; decryption receives the stored tag followed
by tag_length. Both calls accept exactly 12 or 16 and reject every other value. Plaintext/ciphertext length
is explicit and excludes the tag. AAD is an arbitrary binary byte string with
an explicit length. Empty input or AAD may use NULL with zero length.
Key, nonce and tag pointers are always required, including for empty messages.

For an OTP record:

    uint8_t ciphertext[20], seed[20], tag[AES_256_GCM_TAG_SIZE_128];
    /* key[32], iv[12] and framed AAD are supplied by the application. */
    if (!aes_256_gcm_encrypt(ciphertext, sizeof(ciphertext), tag, sizeof(tag),
            seed, sizeof(seed), aad, aad_length, iv, key)) {
            /* Invalid arguments: no output has been changed. */
    }
    if (!aes_256_gcm_decrypt(seed, sizeof(seed), ciphertext, sizeof(ciphertext),
            aad, aad_length, tag, sizeof(tag), iv, key)) {
            /* Invalid arguments or authentication failure: seed is unchanged. */
    }

Decryption hashes/authenticates the ciphertext first, compares every configured tag byte,
and writes plaintext only after successful verification. Consequently a bad
key, nonce, AAD, ciphertext or tag cannot leave unauthenticated plaintext in
the caller's output. If the output already contains sensitive data, callers
remain responsible for clearing that pre-existing data on failure.

Exact in-place input/output is supported, as are disjoint buffers. Shifted
input/output overlap is rejected. Writable output must not overlap the AAD,
key, nonce or tag; encryption's writable tag must not overlap its inputs or
output. Output capacity is checked before writing. Every buffer must still
cover its stated size; the library cannot validate the caller's allocation.
Concurrent mutation of input/key/AAD/tag buffers is not supported.

The maximum data length is 2^36 - 32 bytes, enforcing SP 800-38D's bound and
preventing counter exhaustion. AAD lengths whose bit length overflows uint64_t
are rejected before access. Key schedules and local authentication/keystream
buffers are erased before return. There is no mutable global state.

## Application responsibilities

Supply a fresh nonce for every encryption under a given key. A per-user fixed
nonce is not acceptable when that user's record is re-encrypted. Nonces are
public and may be stored beside the ciphertext. The caller must arrange
uniqueness across all writers and observe the standard's per-key usage limits.
This implementation neither generates nonces nor tracks their use.

For the planned user binding, construct canonical, unambiguous AAD from a
format/version marker, length-prefixed username and the complete password
hash. AAD is authenticated but not encrypted. Authentication failure must
never cause a fallback to password-only authentication. AAD changes (including
password changes) require authenticated recovery using the old AAD, followed
by re-encryption with a fresh nonce and an atomic database update.

The tag buffer must cover exactly the selected tag length; 12-byte mode never
reads or writes a thirteenth byte. GCM truncates the full tag to its leftmost
12 bytes in 96-bit mode. The application must fix/enforce the chosen tag length
for each key/profile and must not allow untrusted input to downgrade a record
from 16 to 12 bytes. The library cannot track that policy in its stateless API.

The GCM key is already a 32-byte binary key. Passphrase strengthening, key
rotation, configuration-file permissions and encrypted-record versioning
belong in a separate application/storage layer.

## Validation and references

The AES test contains the FIPS 197 AES-256 example and the four SP 800-38A
AES-256 ECB examples, including independent decrypt, in-place, context-erasure
and invalid-argument checks: 615 checks total.

The GCM test embeds 50 NIST CAVP cases: the first vector in each plaintext/AAD
length group with IVlen=96 and Taglen=96 or 128 from gcmEncryptExtIV256.rsp (CAVS 14.0,
generated 2012-08-31). It also checks all single-bit changes to the key, nonce,
AAD, ciphertext and tag for a 20-byte OTP record, no plaintext release,
capacity/overlap/length failures and empty messages, plus exact-size short-tag allocations and invalid tag lengths:
4569 checks total.

Development validation additionally checked every matching fixed-profile case
in the NIST files: 750 encryption cases and 750 decryption cases, including
386 expected failures. It also cross-checked 500 deterministic random AES block
and GCM cases against Python cryptography's independent implementation. These
larger external datasets are not required by the shipped self-contained tests.
The NIST response files were retrieved from their copy in the pyca/cryptography
vector repository after the direct NIST ZIP download was unavailable.

Both included tests pass GCC C11 -Wall -Wextra -Wpedantic -Werror builds and
AddressSanitizer/UndefinedBehaviorSanitizer. LeakSanitizer was disabled because
of the test environment's process-namespace restrictions; the modules do not
allocate memory. The code is written with endian-independent byte operations.
No big-endian hardware execution or independent security audit was performed.

References (no third-party implementation source was copied):

* FIPS 197, updated 2023: https://doi.org/10.6028/NIST.FIPS.197-upd1
* SP 800-38D, GCM/GHASH/GCTR Algorithms 1-5:
  https://doi.org/10.6028/NIST.SP.800-38D
* SP 800-38A, Appendix F.1.5-F.1.6:
  https://doi.org/10.6028/NIST.SP.800-38A
* NIST GCM test vectors:
  https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
* NIST response-file mirror:
  https://github.com/pyca/cryptography/tree/main/vectors/cryptography_vectors/ciphers/AES/GCM
