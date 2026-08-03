/*
 * sha256.h - simple, portable SHA-256 implementation (C11, procedural)
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

#ifndef _SHA256_H
#define _SHA256_H

#include <stddef.h>
#include <stdint.h>

#if 1
#define SHA256_TESTING
#endif

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[SHA256_BLOCK_SIZE];
    size_t datalen;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void sha256(uint8_t out[SHA256_DIGEST_SIZE], const void *data, size_t len);

#endif
