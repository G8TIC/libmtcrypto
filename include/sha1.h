/*
 * sha1.h - simple, portable SHA1 implementation (C11, procedural)
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

#ifndef _SHA1_H
#define _SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

typedef struct sha1_ctx {
    uint32_t state[5];
    uint64_t total_length;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    size_t buffer_length;
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *);
void sha1_update(sha1_ctx_t *, const void *, size_t);
void sha1_final(sha1_ctx_t *, uint8_t out[SHA1_DIGEST_SIZE]);
void sha1(uint8_t *, const void *, size_t);

#endif
