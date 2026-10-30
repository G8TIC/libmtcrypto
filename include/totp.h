/*
 * totp.h -- binary-secret TOTP generation and verification (RFC 6238)
 * Copyright (C) 2026 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef TOTP_H
#define TOTP_H

#include <stddef.h>
#include <stdint.h>

#define TOTP_SECRET_SIZE		20
#define TOTP_MIN_SECRET_SIZE		20
#define TOTP_MAX_SECRET_SIZE		128
#define TOTP_TIME_STEP_SECONDS		30
#define TOTP_DIGITS			6
#define TOTP_MODULUS			1000000
#define TOTP_DEFAULT_WINDOW_STEPS	1
#define TOTP_MAX_WINDOW_STEPS		2

/* HMAC-SHA1, six digits, T0=0, 30-second periods. Time is Unix UTC seconds. */
/* Secrets are raw binary bytes; no allocation, clock access or mutable global state. */
/* Returns 1 on success, 0 for invalid arguments; token is unchanged on failure. */
int totp_generate(uint32_t *token, const uint8_t *secret, size_t secret_length, uint64_t unix_time);

/* Returns 1 on a match, 0 for a mismatch or invalid arguments. */
/* window_steps accepts current +/- N periods (0..TOTP_MAX_WINDOW_STEPS). */
/* matched_step may be NULL; otherwise receives the newest matching time-step on success only. */
/* All eligible periods are checked. The caller must enforce attempt limits and consume/reject replayed steps. */
/* A numeric token must be parsed from exactly six decimal digits by the caller, preserving leading zeros in the UI. */
int totp_verify(const uint8_t *secret, size_t secret_length, uint32_t token, uint64_t unix_time,
	unsigned int window_steps, uint64_t *matched_step);

#endif
