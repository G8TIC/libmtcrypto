
#ifndef _HMAC_SHA512_H
#define _HMAC_SHA512_H

#include <stddef.h>
#include <stdint.h>

#include "sha512.h"

#define HMAC_SHA512_BLOCK_SIZE  128
#define HMAC_SHA512_DIGEST_SIZE 64

typedef struct hmac_sha512_ctx {
        sha512_ctx_t inner_ctx;
        sha512_ctx_t outer_ctx;
} hmac_sha512_ctx_t;


void hmac_sha512_init(hmac_sha512_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha512_update(hmac_sha512_ctx_t *ctx, const void *data, size_t data_len);
void hmac_sha512_final(hmac_sha512_ctx_t *ctx, uint8_t out[HMAC_SHA512_DIGEST_SIZE]);
void hmac_sha512(uint8_t out[HMAC_SHA512_DIGEST_SIZE], const uint8_t *key, size_t key_len, const void *data, size_t data_len);

#endif

