/*
 * sha512.h - simple, portable SHA-512 implementation (C11, procedural)
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

#ifndef _SHA512_H
#define _SHA512_H

#include <stdint.h>
#include <stddef.h>

#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE  64

typedef struct sha512_ctx {
    uint64_t state[8];
    uint8_t buffer[SHA512_BLOCK_SIZE];
    uint64_t bitlen_high;
    uint64_t bitlen_low;
    size_t buffer_len;
} sha512_ctx_t;

void sha512_init(sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const void *data, size_t len);
void sha512_final(sha512_ctx_t *ctx, uint8_t out[SHA512_DIGEST_SIZE]);
void sha512(uint8_t out[SHA512_DIGEST_SIZE], const void *data, size_t len);

#endif
