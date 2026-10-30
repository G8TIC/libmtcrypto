/*
 * aes_256.c -- AES-256 from FIPS 197, portable C11, column-major state.
 * Copyright (C) 2026 Mike Tubby G8TIC and contributors.
 *
 * SPDX-License-Identifier: MIT
 *
 * Arithmetic S-boxes avoid secret-indexed lookup tables. This is a small,
 * conservative implementation, not an independently audited side-channel guarantee.
 */

#include <stddef.h>
#include <string.h>

#include "aes_256.h"
#include "secure.h"

#define READY UINT32_C(0x41455332)

static uint8_t multiply(uint8_t a, uint8_t b)
{
	uint8_t result = 0;

	for (unsigned int i = 0; i < 8; ++i) {
		result ^= a & (uint8_t)(0U - (unsigned int)(b & 1U));
		a = (uint8_t)((a << 1) ^ (0x1bU & (0U - (unsigned int)(a >> 7))));
		b >>= 1;
	}
	return result;
}

static uint8_t rotate(uint8_t x, unsigned int n)
{
	return (uint8_t)((x << n) | (x >> (8U - n)));
}

static uint8_t inverse(uint8_t x)
{
	uint8_t result = 1;
	unsigned int exponent = 254;

	/* x^254 in GF(2^8); the fixed exponent also maps zero to zero. */
	for (unsigned int i = 0; i < 8; ++i) {
		if (exponent & 1U) {
			result = multiply(result, x);
		}
		x = multiply(x, x);
		exponent >>= 1;
	}
	return result;
}

static uint8_t substitute(uint8_t x)
{
	uint8_t y = inverse(x);

	return (uint8_t)(y ^ rotate(y, 1) ^ rotate(y, 2) ^ rotate(y, 3) ^ rotate(y, 4) ^ 0x63U);
}

static uint8_t inverse_substitute(uint8_t x)
{
	return inverse((uint8_t)(rotate(x, 1) ^ rotate(x, 3) ^ rotate(x, 6) ^ 0x05U));
}

static void add_key(uint8_t state[16], const uint8_t *key)
{
	for (size_t i = 0; i < 16; ++i) {
		state[i] ^= key[i];
	}
}

static void shift_rows(uint8_t state[16], int decrypt)
{
	uint8_t copy[16];

	memcpy(copy, state, sizeof(copy));
	for (size_t row = 0; row < 4; ++row) {
		for (size_t column = 0; column < 4; ++column) {
			size_t source = decrypt ? (column + 4 - row) % 4 : (column + row) % 4;

			state[column * 4 + row] = copy[source * 4 + row];
		}
	}
	secure_clear(copy, sizeof(copy));
}

static void mix_columns(uint8_t state[16], int decrypt)
{
	static const uint8_t forward[4] = {2, 3, 1, 1};
	static const uint8_t backward[4] = {14, 11, 13, 9};
	const uint8_t *factors = decrypt ? backward : forward;
	uint8_t copy[4];

	for (size_t column = 0; column < 4; ++column) {
		memcpy(copy, state + column * 4, 4);
		for (size_t row = 0; row < 4; ++row) {
			uint8_t value = 0;

			for (size_t i = 0; i < 4; ++i) {
				value ^= multiply(copy[(row + i) % 4], factors[i]);
			}
			state[column * 4 + row] = value;
		}
	}
	secure_clear(copy, sizeof(copy));
}

int aes_256_init(aes_256_ctx_t *ctx, const uint8_t key[32])
{
	uint8_t word[4];
	uint8_t rcon = 1;

	if (!ctx || !key) {
		return 0;
	}
	ctx->ready = 0;
	memcpy(ctx->round_key, key, 32);
	for (size_t offset = 32; offset < AES_256_ROUND_KEY_SIZE; offset += 4) {
		memcpy(word, ctx->round_key + offset - 4, 4);
		if (offset % 32 == 0) {
			uint8_t first = word[0];

			word[0] = substitute(word[1]) ^ rcon;
			word[1] = substitute(word[2]);
			word[2] = substitute(word[3]);
			word[3] = substitute(first);
			rcon = multiply(rcon, 2);
		} else if (offset % 32 == 16) {
			for (size_t i = 0; i < 4; ++i) {
				word[i] = substitute(word[i]);
			}
		}
		for (size_t i = 0; i < 4; ++i) {
			ctx->round_key[offset + i] = ctx->round_key[offset + i - 32] ^ word[i];
		}
	}
	secure_clear(word, sizeof(word));
	ctx->ready = READY;
	return 1;
}

int aes_256_encrypt_block(uint8_t out[16], const uint8_t in[16], const aes_256_ctx_t *ctx)
{
	uint8_t state[16];

	if (!out || !in || !ctx || ctx->ready != READY) {
		return 0;
	}
	memcpy(state, in, sizeof(state));
	add_key(state, ctx->round_key);
	for (unsigned int round = 1; round <= 14; ++round) {
		for (size_t i = 0; i < 16; ++i) {
			state[i] = substitute(state[i]);
		}
		shift_rows(state, 0);
		if (round != 14) {
			mix_columns(state, 0);
		}
		add_key(state, ctx->round_key + round * 16);
	}
	memcpy(out, state, sizeof(state));
	secure_clear(state, sizeof(state));
	return 1;
}

int aes_256_decrypt_block(uint8_t out[16], const uint8_t in[16], const aes_256_ctx_t *ctx)
{
	uint8_t state[16];

	if (!out || !in || !ctx || ctx->ready != READY) {
		return 0;
	}
	memcpy(state, in, sizeof(state));
	add_key(state, ctx->round_key + 14 * 16);
	for (int round = 13; round >= 0; --round) {
		shift_rows(state, 1);
		for (size_t i = 0; i < 16; ++i) {
			state[i] = inverse_substitute(state[i]);
		}
		add_key(state, ctx->round_key + round * 16);
		if (round) {
			mix_columns(state, 1);
		}
	}
	memcpy(out, state, sizeof(state));
	secure_clear(state, sizeof(state));
	return 1;
}

void aes_256_clear(aes_256_ctx_t *ctx)
{
	secure_clear(ctx, ctx ? sizeof(*ctx) : 0);
}

int aes_256_encrypt(uint8_t out[16], const uint8_t in[16], const uint8_t key[32])
{
	aes_256_ctx_t ctx;
	int result = aes_256_init(&ctx, key) && aes_256_encrypt_block(out, in, &ctx);

	aes_256_clear(&ctx);
	return result;
}

int aes_256_decrypt(uint8_t out[16], const uint8_t in[16], const uint8_t key[32])
{
	aes_256_ctx_t ctx;
	int result = aes_256_init(&ctx, key) && aes_256_decrypt_block(out, in, &ctx);

	aes_256_clear(&ctx);
	return result;
}
