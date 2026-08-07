
#include "totp_auth.h"

#include "base32.h"
#include "hmac_sha1.h"
#include "secure.h"

#include <stddef.h>
#include <stdint.h>

#define TOTP_TIME_STEP_SECONDS 30
#define TOTP_MODULUS           1000000
#define TOTP_WINDOW_STEPS      2

#define SHA1_DIGEST_SIZE       20
#define TOTP_MAX_SECRET_BYTES  128


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
     * RFC 4226 dynamic truncation.
     */
    offset = digest[SHA1_DIGEST_SIZE - 1] & 0x0f;

    binary_code =
        ((uint32_t)(digest[offset] & 0x7f) << 24) |
        ((uint32_t)digest[offset + 1] << 16) |
        ((uint32_t)digest[offset + 2] << 8) |
        ((uint32_t)digest[offset + 3]);

    secure_clear(counter_data, sizeof(counter_data));
    secure_clear(digest, sizeof(digest));

    return binary_code % TOTP_MODULUS;
}


int totp_auth_at(const char *secret, uint32_t user_code, time_t now)
{
    uint8_t secret_data[TOTP_MAX_SECRET_BYTES];
    size_t secret_length = 0;
    uint64_t current_counter;
    uint32_t match = 0;
    int step;

    if (secret == NULL) {
        return 0;
    }

    if (user_code >= TOTP_MODULUS) {
        return 0;
    }

    if (now < (time_t)0) {
        return 0;
    }

    if (!base32_decode(secret, secret_data, sizeof(secret_data), &secret_length)) {
        secure_clear(secret_data, sizeof(secret_data));
        return 0;
    }

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
     * Do not return immediately after finding a match. Checking the
     * complete window reduces timing differences between positions
     * within the accepted window.
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
        difference = candidate_code ^ user_code;

        /*
         * Convert difference == 0 into 1, and non-zero into 0,
         * without a data-dependent branch.
         */
        is_equal = ((difference | (0 - difference)) >> 31) ^ 1;
        match |= is_equal;
    }

    secure_clear(secret_data, sizeof(secret_data));

    return match;
}


int totp_auth(const char *secret, uint32_t user_code)
{
    time_t now = time(NULL);

    if (now == (time_t)-1) {
        return 0;
    }

    return totp_auth_at(secret, user_code, now);
}

