/*
 * hmac-sha512.x - simple, portable HMAC-SHA-512 implementation (C11, procedural)
 * Copyright (C) 2025 Mike Tubby G8TIC mike@tubby.org and contributors
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

#include "hmac_sha512.h"

#define IPAD 0x36
#define OPAD 0x5c


/*
 * secure_clear() - clear sensitive temporary data
 *
 * The volatile pointer should prevent the compiler's optimiser from removing the
 * memory writes because the memory is not subsequently read.
 */
static void secure_clear(void *data, size_t len)
{
        volatile uint8_t *p = data;

        while (len) {
                *p++ = 0;
                --len;
        }
}


/*
 * hmac_sha512_init() - initialise a streaming HMAC-SHA-512 operation
 *
 * HMAC is defined as:
 *
 *     HMAC(K, m) =
 *         SHA512((K xor opad) ||
 *                SHA512((K xor ipad) || m))
 *
 * This function prepares both SHA-512 contexts:
 *
 *     inner_ctx = SHA512 initial state followed by K xor ipad
 *     outer_ctx = SHA512 initial state followed by K xor opad
 */
void hmac_sha512_init(hmac_sha512_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
        uint8_t key_block[HMAC_SHA512_BLOCK_SIZE];
        uint8_t inner_pad[HMAC_SHA512_BLOCK_SIZE];
        uint8_t outer_pad[HMAC_SHA512_BLOCK_SIZE];

        /*
         * HMAC keys longer than the SHA-512 block size are first reduced to one SHA-512 digest.
         * Shorter keys are padded with zeroes to the block size.
         */
        memset(key_block, 0, sizeof(key_block));

        if (key_len > HMAC_SHA512_BLOCK_SIZE) {
                uint8_t hash[HMAC_SHA512_DIGEST_SIZE];
        
                sha512(hash, key, key_len);
                memcpy(key_block, hash, HMAC_SHA512_DIGEST_SIZE);
                secure_clear(hash, HMAC_SHA512_DIGEST_SIZE);
        } else {
                memcpy(key_block, key, key_len);
        }

        /*
         * Construct the HMAC inner and outer padding blocks.
         */
        for (int i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i) {
                inner_pad[i] = (uint8_t)(key_block[i] ^ IPAD);
                outer_pad[i] = (uint8_t)(key_block[i] ^ OPAD);
        }

        /*
         * Preload the inner and outer SHA-512 contexts with their respective
         * padding blocks.
         */
        sha512_init(&ctx->inner_ctx);
        sha512_update(&ctx->inner_ctx, inner_pad, sizeof(inner_pad));

        sha512_init(&ctx->outer_ctx);
        sha512_update(&ctx->outer_ctx, outer_pad, sizeof(outer_pad));

        secure_clear(key_block, sizeof(key_block));
        secure_clear(inner_pad, sizeof(inner_pad));
        secure_clear(outer_pad, sizeof(outer_pad));
}


/*
 * hmac_sha512_update() - add data to a streaming HMAC-SHA-512 operation
 */
void hmac_sha512_update(hmac_sha512_ctx_t *ctx, const void *data, size_t data_len)
{
        if (data && data_len > 0) {
                sha512_update(&ctx->inner_ctx, data, data_len);
        }
}


/*
 * hmac_sha512_final() - complete a streaming HMAC-SHA-512 operation
 */
void hmac_sha512_final(hmac_sha512_ctx_t *ctx, uint8_t out[HMAC_SHA512_DIGEST_SIZE])
{
        uint8_t inner_digest[HMAC_SHA512_DIGEST_SIZE];

        sha512_final(&ctx->inner_ctx, inner_digest);
        sha512_update(&ctx->outer_ctx, inner_digest, sizeof(inner_digest));
        sha512_final(&ctx->outer_ctx, out);
        
        secure_clear(inner_digest, sizeof(inner_digest));
        secure_clear(ctx, sizeof(hmac_sha512_ctx_t));
}


/*
 * hmac_sha512() - one-shot HMAC-SHA-512 wrapper
 */
void hmac_sha512(uint8_t out[HMAC_SHA512_DIGEST_SIZE], const uint8_t *key, size_t key_len, const void *data, size_t data_len)
{
        if (out && key && data && key_len && data_len) {
                hmac_sha512_ctx_t ctx;

                hmac_sha512_init(&ctx, key, key_len);
                hmac_sha512_update(&ctx, data, data_len);
                hmac_sha512_final(&ctx, out);
        }
}
        