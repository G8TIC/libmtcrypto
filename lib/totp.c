/*
 * totp.c -- binary-secret TOTP generation and verification (RFC 6238)
 * Copyright (C) 2026 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * SPDX-License-Identifier: MIT
 */
#include "totp.h"
#include "hmac_sha1.h"
#include "secure.h"

static int valid_secret(const uint8_t *secret, size_t length)
{
	return secret && length >= TOTP_MIN_SECRET_SIZE && length <= TOTP_MAX_SECRET_SIZE;
}

static uint32_t generate_counter(const uint8_t *secret, size_t length, uint64_t counter)
{
	uint8_t counter_data[8];
	uint8_t digest[HMAC_SHA1_DIGEST_SIZE];
	unsigned int offset;
	uint32_t binary_code;

	/* HOTP encodes the moving counter as an unsigned 64-bit big-endian integer. */
	for (size_t i = 0; i < sizeof(counter_data); ++i) {
		counter_data[7 - i] = (uint8_t)(counter >> (i * 8));
	}
	hmac_sha1(digest, secret, length, counter_data, sizeof(counter_data));
	offset = digest[HMAC_SHA1_DIGEST_SIZE - 1] & 0x0f;
	binary_code = ((uint32_t)(digest[offset] & 0x7f) << 24) | ((uint32_t)digest[offset + 1] << 16) |
		((uint32_t)digest[offset + 2] << 8) | (uint32_t)digest[offset + 3];
	secure_clear(counter_data, sizeof(counter_data));
	secure_clear(digest, sizeof(digest));
	return binary_code % TOTP_MODULUS;
}

int totp_generate(uint32_t *token, const uint8_t *secret, size_t length, uint64_t unix_time)
{
	if (!token || !valid_secret(secret, length)) {
		return 0;
	}
	*token = generate_counter(secret, length, unix_time / TOTP_TIME_STEP_SECONDS);
	return 1;
}

int totp_verify(const uint8_t *secret, size_t length, uint32_t token, uint64_t unix_time, unsigned int window_steps, uint64_t *matched_step)
{
	uint64_t current = unix_time / TOTP_TIME_STEP_SECONDS;
	uint64_t selected = 0;
	uint32_t match = 0;

	if (!valid_secret(secret, length) || token >= TOTP_MODULUS || window_steps > TOTP_MAX_WINDOW_STEPS) {
		return 0;
	}
	for (int delta = -(int)window_steps; delta <= (int)window_steps; ++delta) {
		uint64_t candidate, mask;
		uint32_t code, difference, equal;

		/* Guard arithmetic at the epoch and at the counter limit. */
		if (delta < 0) {
			if (current < (uint64_t)(-delta)) {
				continue;
			}
			candidate = current - (uint64_t)(-delta);
		} else {
			if (UINT64_MAX - current < (uint64_t)delta) {
				continue;
			}
			candidate = current + (uint64_t)delta;
		}
		code = generate_counter(secret, length, candidate);
		difference = code ^ token;
		equal = ((difference | (0U - difference)) >> 31) ^ 1U;
		mask = UINT64_C(0) - (uint64_t)equal;
		selected = (selected & ~mask) | (candidate & mask);
		match |= equal;
	}
	if (match && matched_step) {
		*matched_step = selected;
	}
	return (int)match;
}
