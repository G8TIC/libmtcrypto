/*
 * totp_test.c -- RFC 4226 / RFC 6238 vectors and TOTP API boundary tests
 * Copyright (C) 2026 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * SPDX-License-Identifier: MIT
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "totp.h"

static unsigned int checks;
static const uint8_t secret[] = "12345678901234567890";

static void check(int condition, const char *description)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "FAIL: %s\n", description);
		exit(EXIT_FAILURE);
	}
}

static void test_vectors(void)
{
	/* RFC 4226 Appendix D: six-digit HOTP values, mapped to TOTP periods 0..9. */
	static const uint32_t hotp[] = { 755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489 };
	/* RFC 6238 Appendix B publishes eight digits: six digits are the same result modulo 10^6. */
	static const struct {
		uint64_t time;
		uint32_t eight_digits;
	} rfc6238[] = {
		{ UINT64_C(59), 94287082 },
		{ UINT64_C(1111111109), 7081804 },
		{ UINT64_C(1111111111), 14050471 },
		{ UINT64_C(1234567890), 89005924 },
		{ UINT64_C(2000000000), 69279037 },
		{ UINT64_C(20000000000), 65353130 }
	};
	uint32_t token;
	uint64_t matched;

	for (size_t i = 0; i < sizeof(hotp) / sizeof(hotp[0]); ++i) {
		check(totp_generate(&token, secret, sizeof(secret) - 1, (uint64_t)i * 30), "HOTP generation succeeds");
		check(token == hotp[i], "RFC 4226 six-digit vector");
	}
	for (size_t i = 0; i < sizeof(rfc6238) / sizeof(rfc6238[0]); ++i) {
		check(totp_generate(&token, secret, sizeof(secret) - 1, rfc6238[i].time), "TOTP generation succeeds");
		check(token == rfc6238[i].eight_digits % 1000000, "RFC 6238 six-digit SHA1 vector");
		matched = UINT64_MAX;
		check(totp_verify(secret, sizeof(secret) - 1, token, rfc6238[i].time, 0, &matched), "RFC vector verifies");
		check(matched == rfc6238[i].time / 30, "RFC matched time-step");
	}
}

static void test_periods(void)
{
	uint32_t before, after, token;
	uint64_t matched;
	char displayed[7];
	const uint64_t now = UINT64_C(1234567890);

	check(totp_generate(&before, secret, sizeof(secret) - 1, 29), "generate before period boundary");
	check(totp_generate(&after, secret, sizeof(secret) - 1, 30), "generate at period boundary");
	check(before == 755224 && after == 287082, "period transition at 30 seconds");
	check(totp_generate(&token, secret, sizeof(secret) - 1, UINT64_C(1111111109)), "generate leading-zero code");
	(void)snprintf(displayed, sizeof(displayed), "%06" PRIu32, token);
	check(!strcmp(displayed, "081804"), "six-digit display preserves leading zero");

	for (int delta = -3; delta <= 3; ++delta) {
		uint64_t when = delta < 0 ? now - (uint64_t)(-delta) * 30 : now + (uint64_t)delta * 30;

		check(totp_generate(&token, secret, sizeof(secret) - 1, when), "generate neighbour period");
		for (unsigned int window = 0; window <= TOTP_MAX_WINDOW_STEPS; ++window) {
			int expected = delta >= -(int)window && delta <= (int)window;

			matched = UINT64_MAX;
			check(totp_verify(secret, sizeof(secret) - 1, token, now, window, &matched) == expected,
				"window accepts exactly the configured periods");
			check(matched == (expected ? when / 30 : UINT64_MAX), "matched step changed only on success");
		}
	}
	check(totp_verify(secret, sizeof(secret) - 1, 755224, 0, 2, &matched), "epoch zero is valid");
	check(matched == 0, "epoch matched step is zero");
	check(!totp_verify(secret, sizeof(secret) - 1, 520489, 0, 2, NULL), "epoch does not wrap negative periods");
	check(totp_generate(&token, secret, sizeof(secret) - 1, UINT64_MAX), "maximum uint64 Unix timestamp");
	check(token == 277486, "maximum timestamp independently cross-checked with Python HMAC");
	check(totp_verify(secret, sizeof(secret) - 1, token, UINT64_MAX, 2, &matched), "maximum timestamp verifies");
	check(matched == UINT64_MAX / 30, "maximum timestamp returns correct time-step");
}

static void test_arguments(void)
{
	uint8_t binary[128];
	uint32_t token = UINT32_MAX;
	uint64_t matched = UINT64_MAX;

	for (size_t i = 0; i < sizeof(binary); ++i) {
		binary[i] = (uint8_t)i;
	}
	check(!totp_generate(NULL, secret, sizeof(secret) - 1, 0), "reject NULL output");
	check(!totp_generate(&token, NULL, 20, 0), "reject NULL secret");
	check(!totp_generate(&token, secret, 0, 0), "reject empty secret");
	check(!totp_generate(&token, secret, 19, 0), "reject short secret");
	check(!totp_generate(&token, binary, 129, 0), "reject oversized secret before reading it");
	check(token == UINT32_MAX, "generation leaves output unchanged on failure");
	check(!totp_verify(NULL, 20, 755224, 0, 1, &matched), "verification rejects NULL secret");
	check(!totp_verify(secret, 19, 755224, 0, 1, &matched), "verification rejects short secret");
	check(!totp_verify(binary, 129, 755224, 0, 1, &matched), "verification rejects oversized secret");
	check(!totp_verify(secret, sizeof(secret) - 1, 1000000, 0, 1, &matched), "reject seven-digit token");
	check(!totp_verify(secret, sizeof(secret) - 1, UINT32_MAX, 0, 1, &matched), "reject maximum uint32 token");
	check(!totp_verify(secret, sizeof(secret) - 1, 755224, 0, 3, &matched), "reject unsupported window");
	check(!totp_verify(secret, sizeof(secret) - 1, 755224, 0, UINT32_MAX, &matched), "reject huge window");
	check(!totp_verify(secret, sizeof(secret) - 1, 999999, 0, 0, &matched), "reject incorrect code");
	check(matched == UINT64_MAX, "verification leaves output unchanged on failure");
	check(totp_verify(secret, sizeof(secret) - 1, 755224, 0, 0, NULL), "matched-step output is optional");
	check(totp_generate(&token, binary, 20, UINT64_C(1234567890)), "binary secret including NUL");
	check(token == 616470, "binary secret independently cross-checked with Python HMAC");
	check(totp_generate(&token, binary, sizeof(binary), UINT64_C(1234567890)), "maximum secret length");
	check(token == 202681, "128-byte secret independently cross-checked with Python HMAC");
	for (size_t i = 0; i < sizeof(binary); ++i) {
		check(binary[i] == (uint8_t)i, "secret bytes remain unchanged");
	}
}

int main(void)
{
	test_vectors();
	test_periods();
	test_arguments();
	printf("PASS: %u TOTP checks\n", checks);
	return EXIT_SUCCESS;
}
