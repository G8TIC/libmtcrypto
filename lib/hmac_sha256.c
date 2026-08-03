/*
 * hmac_sha256.c - simple, portable HMAC-SHA-256 implementation in procedural C11
 * Copyright (C) 2025-2026 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hmac_sha256.h"
#include "secure.h"


#define IPAD 0x36
#define OPAD 0x5c


/*
 * hmac_sha256_init() - initialise a streaming HMAC-SHA256 operation
 */
void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
        uint8_t key_block[HMAC_SHA256_BLOCK_SIZE];
        uint8_t inner_pad[HMAC_SHA256_BLOCK_SIZE];
        uint8_t outer_pad[HMAC_SHA256_BLOCK_SIZE];

        /*
         * RFC 2104: If the key is longer than the SHA-256 block size then
         * truncate it by taking the sha256() hask of the key.
         */
        memset(key_block, 0, sizeof(key_block));

        if (key_len > HMAC_SHA256_BLOCK_SIZE) {
                uint8_t hash[HMAC_SHA256_DIGEST_SIZE];
        
                sha256(hash, key, key_len);
                memcpy(key_block, hash, HMAC_SHA256_DIGEST_SIZE);
                secure_clear(hash, HMAC_SHA256_DIGEST_SIZE);
        } else {
                memcpy(key_block, key, key_len);
        }

        /*
         * Prepare the inner and outer pads.
         */
        for (int i = 0; i < HMAC_SHA256_BLOCK_SIZE; ++i) {
                inner_pad[i] = (uint8_t)(key_block[i] ^ IPAD);
                outer_pad[i] = (uint8_t)(key_block[i] ^ OPAD);
        }

        /*
         * Preload the two SHA-256 contexts.
         *
         * Subsequent message data is appended to inner_ctx. At finalisation,
         * the inner digest is appended to outer_ctx.
         */
        sha256_init(&ctx->inner_ctx);
        sha256_update(&ctx->inner_ctx, inner_pad, sizeof(inner_pad));

        sha256_init(&ctx->outer_ctx);
        sha256_update(&ctx->outer_ctx, outer_pad, sizeof(outer_pad));

        secure_clear(key_block, sizeof(key_block));
        secure_clear(inner_pad, sizeof(inner_pad));
        secure_clear(outer_pad, sizeof(outer_pad));
}


/*
 * hmac_sha256_update() - add message data to a streaming HMAC-SHA256 operation
 */
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t data_len)
{
        if (data_len > 0)
                sha256_update(&ctx->inner_ctx, data, data_len);
}


/*
 * hmac_sha256_final() - complete a streaming HMAC-SHA256 operation
 */
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t out[HMAC_SHA256_DIGEST_SIZE])
{
        uint8_t inner_digest[HMAC_SHA256_DIGEST_SIZE];

        sha256_final(&ctx->inner_ctx, inner_digest);
        sha256_update(&ctx->outer_ctx, inner_digest, sizeof(inner_digest));
        sha256_final(&ctx->outer_ctx, out);

        secure_clear(inner_digest, sizeof(inner_digest));
        secure_clear(ctx, sizeof(hmac_sha256_ctx_t));
}


/*
 * hmac_sha256() - one-shot HMAC-SHA256 wrapper
 */
void hmac_sha256(uint8_t out[HMAC_SHA256_DIGEST_SIZE], const uint8_t *key, size_t key_len, const void *data, size_t data_len)
{
        hmac_sha256_ctx_t ctx;

        hmac_sha256_init(&ctx, key, key_len);
        hmac_sha256_update(&ctx, data, data_len);
        hmac_sha256_final(&ctx, out);
}

