/* aes_256.h -- AES-256 block cipher, FIPS 197. SPDX-License-Identifier: MIT */
#ifndef MTCRYPTO_AES_256_H
#define MTCRYPTO_AES_256_H
#include <stdint.h>

#define AES_256_KEY_SIZE 32U
#define AES_256_BLOCK_SIZE 16U
#define AES_256_ROUND_KEY_SIZE 240U

typedef struct {
	uint8_t round_key[AES_256_ROUND_KEY_SIZE];
	uint32_t ready;
} aes_256_ctx_t;

/* All functions return 1 on success, 0 for invalid arguments/context. */
/* Initialise before use; context must not overlap key or data buffers. */
int aes_256_init(aes_256_ctx_t *ctx, const uint8_t key[AES_256_KEY_SIZE]);
/* Exactly one block; exact in-place operation is supported. No padding or mode. */
int aes_256_encrypt_block(uint8_t out[16], const uint8_t in[16], const aes_256_ctx_t *ctx);
int aes_256_decrypt_block(uint8_t out[16], const uint8_t in[16], const aes_256_ctx_t *ctx);
void aes_256_clear(aes_256_ctx_t *ctx);
/* Single-shot alternatives expand and erase the key schedule on each call. */
int aes_256_encrypt(uint8_t out[16], const uint8_t in[16], const uint8_t key[32]);
int aes_256_decrypt(uint8_t out[16], const uint8_t in[16], const uint8_t key[32]);
#endif
