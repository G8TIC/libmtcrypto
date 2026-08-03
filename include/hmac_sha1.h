
#ifndef _HMAC_SHA1_H
#define _HMAC_SHA1_H

#include <stddef.h>
#include <stdint.h>

#include "sha1.h"

#define HMAC_SHA1_BLOCK_SIZE  64
#define HMAC_SHA1_DIGEST_SIZE 20

typedef struct hmac_sha1_ctx {
        sha1_ctx_t inner_ctx;
        sha1_ctx_t outer_ctx;
} hmac_sha1_ctx_t;

void hmac_sha1_init(hmac_sha1_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha1_update(hmac_sha1_ctx_t *ctx, const void *data, size_t data_len);
void hmac_sha1_final(hmac_sha1_ctx_t *ctx, uint8_t out[HMAC_SHA1_DIGEST_SIZE]);
void hmac_sha1(uint8_t out[HMAC_SHA1_DIGEST_SIZE], const uint8_t *key, size_t key_len, const void *data, size_t data_len);

#endif
