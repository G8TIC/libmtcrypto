/*
 * hmac_sha256.h - simple, portable HMAC-SHA-256 implementation in procedural C11
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

#ifndef _HMAC_SHA256_H
#define _HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

#define HMAC_SHA256_BLOCK_SIZE  64
#define HMAC_SHA256_DIGEST_SIZE 32

typedef struct hmac_sha256_ctx {
        sha256_ctx_t inner_ctx;
        sha256_ctx_t outer_ctx;
} hmac_sha256_ctx_t;


void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t data_len);
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t out[HMAC_SHA256_DIGEST_SIZE]);
void hmac_sha256(uint8_t out[HMAC_SHA256_DIGEST_SIZE], const uint8_t *key, size_t key_len, const void *data, size_t data_len);

#endif
