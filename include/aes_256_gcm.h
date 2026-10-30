/* aes_256_gcm.h -- AES-256-GCM, SP 800-38D. SPDX-License-Identifier: MIT */
#ifndef MTCRYPTO_AES_256_GCM_H
#define MTCRYPTO_AES_256_GCM_H
#include <stddef.h>
#include <stdint.h>

#define AES_256_GCM_KEY_SIZE 32U
#define AES_256_GCM_IV_SIZE 12U
#define AES_256_GCM_TAG_SIZE_96 12U
#define AES_256_GCM_TAG_SIZE_128 16U
#define AES_256_GCM_TAG_SIZE AES_256_GCM_TAG_SIZE_128
#define AES_256_GCM_MAX_DATA_SIZE UINT64_C(68719476704)

/* Fixed profile: 256-bit key, 96-bit nonce, 96- or 128-bit tag. No allocation or RNG. */
/* tag_length must be exactly AES_256_GCM_TAG_SIZE_96 or AES_256_GCM_TAG_SIZE_128. */
/* Caller MUST supply a fresh nonce for every encryption under the same key. */
/* Returns 1 on success, 0 on invalid arguments or failed authentication. */
/* Buffers must cover their stated lengths; output capacity is checked before access. */
/* The application must fix/enforce the tag length for each key/profile; do not infer it from untrusted data. */
/* Exact in-place operation or disjoint buffers only; other output/input overlaps are rejected. */
/* Context is entirely local; independent calls are thread-safe with caller-owned buffers. */
/* NULL data/output/AAD allowed only for zero corresponding lengths. Key/IV/tag are always required. */
/* On failure ALL output bytes remain unchanged, including in-place ciphertext and the encryption tag. */
/* Decrypt authenticates before writing plaintext. The caller owns AAD framing and key/nonce storage. */
int aes_256_gcm_encrypt(uint8_t *ciphertext, size_t capacity, uint8_t *tag, size_t tag_length,
	const uint8_t *plaintext, size_t length, const uint8_t *aad, size_t aad_length,
	const uint8_t iv[12], const uint8_t key[32]);
int aes_256_gcm_decrypt(uint8_t *plaintext, size_t capacity, const uint8_t *ciphertext, size_t length,
	const uint8_t *aad, size_t aad_length, const uint8_t *tag, size_t tag_length, const uint8_t iv[12], const uint8_t key[32]);
#endif
