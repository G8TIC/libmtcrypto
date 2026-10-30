/*
 * aes_256_gcm.c -- SP 800-38D Algorithms 1..5, fixed 96-bit IV / selectable 96- or 128-bit tag.
 * Copyright (C) 2026 Mike Tubby G8TIC and contributors. SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "aes_256.h"
#include "aes_256_gcm.h"
#include "secure.h"

static int overlap(const void *a, size_t a_size, const void *b, size_t b_size)
{
	uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;

	if (!a_size || !b_size) {
		return 0;
	}
	return x <= y ? y - x < a_size : x - y < b_size;
}

static int valid(uint8_t *out, size_t capacity, const uint8_t *in, size_t length,
	const uint8_t *aad, size_t aad_length, const uint8_t *tag, size_t tag_length,
	const uint8_t *iv, const uint8_t *key, int encrypt)
{
	if ((tag_length != 12 && tag_length != 16) || !tag || !iv || !key || (length && (!out || !in)) ||
		(aad_length && !aad) || capacity < length ||
		length > AES_256_GCM_MAX_DATA_SIZE || aad_length > UINT64_MAX / 8) {
		return 0;
	}
	if ((out != in && overlap(out, length, in, length)) || overlap(out, length, aad, aad_length) ||
		overlap(out, length, tag, tag_length) || overlap(out, length, iv, 12) || overlap(out, length, key, 32)) {
		return 0;
	}
	if (encrypt && (overlap(tag, tag_length, in, length) || overlap(tag, tag_length, aad, aad_length) ||
		overlap(tag, tag_length, iv, 12) || overlap(tag, tag_length, key, 32))) {
		return 0;
	}
	return 1;
}

static void store64(uint8_t out[8], uint64_t value)
{
	for (size_t i = 0; i < 8; ++i) {
		out[7 - i] = (uint8_t)(value >> (i * 8));
	}
}

static void multiply(uint8_t value[16], const uint8_t h[16])
{
	uint8_t z[16] = {0}, v[16];

	memcpy(v, h, sizeof(v));
	for (size_t bit = 0; bit < 128; ++bit) {
		uint8_t mask = (uint8_t)(0U - ((value[bit / 8] >> (7 - bit % 8)) & 1U));
		uint8_t reduction = (uint8_t)(0U - (unsigned int)(v[15] & 1U));

		for (size_t i = 0; i < 16; ++i) {
			z[i] ^= v[i] & mask;
		}
		for (size_t i = 15; i > 0; --i) {
			v[i] = (uint8_t)((v[i] >> 1) | (v[i - 1] << 7));
		}
		v[0] = (uint8_t)((v[0] >> 1) ^ (0xe1U & reduction));
	}
	memcpy(value, z, sizeof(z));
	secure_clear(z, sizeof(z));
	secure_clear(v, sizeof(v));
}

static void hash_bytes(uint8_t hash[16], const uint8_t h[16], const uint8_t *data, size_t length)
{
	while (length) {
		size_t count = length < 16 ? length : 16;

		for (size_t i = 0; i < count; ++i) {
			hash[i] ^= data[i];
		}
		multiply(hash, h);
		data += count;
		length -= count;
	}
}

static void authenticate(uint8_t tag[16], const aes_256_ctx_t *ctx, const uint8_t j0[16],
	const uint8_t *aad, size_t aad_length, const uint8_t *ciphertext, size_t length)
{
	uint8_t h[16] = {0}, hash[16] = {0}, lengths[16], mask[16];

	(void)aes_256_encrypt_block(h, h, ctx);
	hash_bytes(hash, h, aad, aad_length);
	hash_bytes(hash, h, ciphertext, length);
	store64(lengths, (uint64_t)aad_length * 8);
	store64(lengths + 8, (uint64_t)length * 8);
	hash_bytes(hash, h, lengths, sizeof(lengths));
	(void)aes_256_encrypt_block(mask, j0, ctx);
	for (size_t i = 0; i < 16; ++i) {
		tag[i] = hash[i] ^ mask[i];
	}
	secure_clear(h, sizeof(h));
	secure_clear(hash, sizeof(hash));
	secure_clear(lengths, sizeof(lengths));
	secure_clear(mask, sizeof(mask));
}

static void counter_crypt(uint8_t *out, const uint8_t *in, size_t length,
	const aes_256_ctx_t *ctx, const uint8_t j0[16])
{
	uint8_t counter[16], stream[16];
	uint32_t n = 1;

	memcpy(counter, j0, sizeof(counter));
	while (length) {
		size_t count = length < 16 ? length : 16;

		++n;
		counter[12] = (uint8_t)(n >> 24);
		counter[13] = (uint8_t)(n >> 16);
		counter[14] = (uint8_t)(n >> 8);
		counter[15] = (uint8_t)n;
		(void)aes_256_encrypt_block(stream, counter, ctx);
		for (size_t i = 0; i < count; ++i) {
			out[i] = in[i] ^ stream[i];
		}
		in += count;
		out += count;
		length -= count;
	}
	secure_clear(counter, sizeof(counter));
	secure_clear(stream, sizeof(stream));
}

int aes_256_gcm_encrypt(uint8_t *ciphertext, size_t capacity, uint8_t *tag, size_t tag_length,
	const uint8_t *plaintext, size_t length, const uint8_t *aad, size_t aad_length,
	const uint8_t iv[12], const uint8_t key[32])
{
	aes_256_ctx_t ctx;
	uint8_t j0[16] = {0}, full_tag[16];

	if (!valid(ciphertext, capacity, plaintext, length, aad, aad_length, tag, tag_length, iv, key, 1)) {
		return 0;
	}
	(void)aes_256_init(&ctx, key);
	memcpy(j0, iv, 12);
	j0[15] = 1;
	counter_crypt(ciphertext, plaintext, length, &ctx, j0);
	authenticate(full_tag, &ctx, j0, aad, aad_length, ciphertext, length);
	memcpy(tag, full_tag, tag_length);
	secure_clear(full_tag, sizeof(full_tag));
	aes_256_clear(&ctx);
	secure_clear(j0, sizeof(j0));
	return 1;
}

int aes_256_gcm_decrypt(uint8_t *plaintext, size_t capacity, const uint8_t *ciphertext, size_t length,
	const uint8_t *aad, size_t aad_length, const uint8_t *tag, size_t tag_length,
	const uint8_t iv[12], const uint8_t key[32])
{
	aes_256_ctx_t ctx;
	uint8_t j0[16] = {0}, expected[16];
	unsigned int difference = 0;

	if (!valid(plaintext, capacity, ciphertext, length, aad, aad_length, tag, tag_length, iv, key, 0)) {
		return 0;
	}
	(void)aes_256_init(&ctx, key);
	memcpy(j0, iv, 12);
	j0[15] = 1;
	authenticate(expected, &ctx, j0, aad, aad_length, ciphertext, length);
	for (size_t i = 0; i < tag_length; ++i) {
		difference |= expected[i] ^ tag[i];
	}
	if (!difference) {
		counter_crypt(plaintext, ciphertext, length, &ctx, j0);
	}
	aes_256_clear(&ctx);
	secure_clear(expected, sizeof(expected));
	secure_clear(j0, sizeof(j0));
	return difference == 0;
}
