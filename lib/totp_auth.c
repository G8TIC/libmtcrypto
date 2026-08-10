/*
 * totp_auth.c -- Time-based OTP token authentication to RFC 6283 
 * Copyright (C) 2026 Mike Tubby G8TIC mike@tubby.org and contributors
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

#include "totp_auth.h"
#include "base32.h"
#include "hmac_sha1.h"
#include "secure.h"

#define TOTP_TIME_STEP_SECONDS	30
#define TOTP_MODULUS		1000000
#define TOTP_WINDOW_STEPS	2
#define TOTP_MIN_SECRET_SIZE	20
#define TOTP_MAX_SECRET_SIZE	128


static uint32_t totp_generate(const uint8_t *secret, size_t secret_length, uint64_t counter)
{
    uint8_t counter_data[8];
    uint8_t digest[SHA1_DIGEST_SIZE];
    uint32_t binary_code;
    unsigned int offset;
    size_t i;

    /*
     * HOTP/TOTP counters are encoded as unsigned 64-bit, big-endian integers.
     */
    for (i = 0; i < sizeof(counter_data); ++i) {
        counter_data[7 - i] = (uint8_t)(counter >> (i * 8));
    }

    hmac_sha1(digest, secret, secret_length, counter_data, sizeof(counter_data));

    /*
     * RFC 4226 dynamic truncation
     */
    offset = digest[SHA1_DIGEST_SIZE - 1] & 0x0f;
    binary_code = ((uint32_t)(digest[offset] & 0x7f) << 24) | ((uint32_t)digest[offset + 1] << 16) | ((uint32_t)digest[offset + 2] << 8) | ((uint32_t)digest[offset + 3]);

    /*
     * clear sensitive memory
     */
    secure_clear(counter_data, sizeof(counter_data));
    secure_clear(digest, sizeof(digest));

    /*
     * return result
     */
    return binary_code % TOTP_MODULUS;
}


/*
 * totp_auth_at() - perform user token authentication at a specific time
 */
int totp_auth_at(const char *secret, uint32_t token, time_t now)
{
    if (secret && token < TOTP_MODULUS && now) {
        uint8_t secret_data[TOTP_MAX_SECRET_SIZE];
        size_t secret_length = 0;

        /*
         * base32 decode the secret
         */
        if (base32_decode(secret, secret_data, sizeof(secret_data), &secret_length)) {

            /*
             * check secret is a valid length
             */
            if (secret_length >= TOTP_MIN_SECRET_SIZE && secret_length <= TOTP_MAX_SECRET_SIZE) {
                uint64_t current_counter;
                uint32_t match = 0;
                int step;

                current_counter = (uint64_t)now / TOTP_TIME_STEP_SECONDS;

                /*
                 * Check all five permitted periods:
                 *
                 *   current - 2
                 *   current - 1
                 *   current
                 *   current + 1
                 *   current + 2
                 *
                 * Do not return immediately after finding a match. Checking the complete window
                 * reduces timing differences between positions within the accepted window
                 */
                for (step = -TOTP_WINDOW_STEPS; step <= TOTP_WINDOW_STEPS; ++step) {
                    uint64_t candidate_counter;
                    uint32_t candidate_code;
                    uint32_t difference;
                    uint32_t is_equal;

                    if (step < 0 && current_counter < (uint64_t)(-step)) {
                        continue;
                    }

                    if (step < 0) {
                        candidate_counter = current_counter - (uint64_t)(-step);
                    } else {
                        candidate_counter = current_counter + (uint64_t)step;
                    }

                    candidate_code = totp_generate(secret_data, secret_length, candidate_counter);
                    difference = candidate_code ^ token;

                    /*
                     * Convert difference == 0 into 1, and non-zero into 0  without a data-dependent branch
                     */
                    is_equal = ((difference | (0 - difference)) >> 31) ^ 1;
                    match |= is_equal;
                }

                secure_clear(secret_data, sizeof(secret_data));

                return match;

            }
        }

        secure_clear(secret_data, sizeof(secret_data));
    }

    return 0;
}


/*
 * totp_auth() - authenticate a user token
 */
int totp_auth(const char *secret, uint32_t token)
{
    return totp_auth_at(secret, token, time(NULL));
}

