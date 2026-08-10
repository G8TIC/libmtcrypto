/*
 * sha512_crypt.c - C implementation of SHA-512-crypt for "$6$" type passwords
 * Author: Mike Tubby mike@tubby.org
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "sha512.h"
#include "sha512_crypt.h"
#include "secure.h"

#define SHA512_CRYPT_PREFIX             "$6$"
#define SHA512_CRYPT_ROUNDS_PREFIX      "rounds="
#define SHA512_CRYPT_DEFAULT_ROUNDS     5000
#define SHA512_CRYPT_MIN_ROUNDS         1000
#define SHA512_CRYPT_MAX_ROUNDS         999999999
#define SHA512_CRYPT_MAX_SALT_LENGTH    16
#define SHA512_CRYPT_DIGEST_LENGTH      64
#define SHA512_CRYPT_ENCODED_LENGTH     86


static const char crypt_base64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


/*
 * sha512_crypt_salt() - ghenerate random salt for a password
 */
int sha512_crypt_salt(char salt[SHA512_CRYPT_SALT_SIZE+1])
{
    if (salt) {
        uint8_t buf[SHA512_CRYPT_SALT_SIZE];

        getrandom(buf, SHA512_CRYPT_SALT_SIZE, 0);

        for (int i = 0; i < SHA512_CRYPT_SALT_SIZE; ++i)
            salt[i] = crypt_base64[buf[i] & 0x3f];

        salt[SHA512_CRYPT_SALT_SIZE] = '\0';
        secure_clear(buf, sizeof(buf));
        return 1;
    }

    return 0;
}


static void sha512_update_repeated_digest(sha512_ctx_t *context, const uint8_t digest[SHA512_CRYPT_DIGEST_LENGTH], size_t total_length)
{
    while (total_length >= SHA512_CRYPT_DIGEST_LENGTH) {
        sha512_update(context, digest, SHA512_CRYPT_DIGEST_LENGTH);
        total_length -= SHA512_CRYPT_DIGEST_LENGTH;
    }

    if (total_length != 0U) {
        sha512_update(context, digest, total_length);
    }
}

/*
 * The SHA-crypt encoding takes three bytes, treats them as a 24-bit integer,
 * and emits the least-significant six bits first.
 */
static int crypt_base64_from_24(uint8_t byte_2, uint8_t byte_1, uint8_t byte_0, unsigned int character_count, char **output, size_t *remaining)
{
    uint32_t value;

    value = ((uint32_t)byte_2 << 16) |
            ((uint32_t)byte_1 << 8) |
            (uint32_t)byte_0;

    while (character_count-- != 0U) {

        if (*remaining <= 1U) {
            return 0;
        }

        **output = crypt_base64[value & 0x3fU];
        ++*output;
        --*remaining;
        value >>= 6;
    }

    return 1;
}

static int append_data(char **output, size_t *remaining, const char *data, size_t length)
{
    if (length >= *remaining) {
        return 0;
    }

    memcpy(*output, data, length);
    *output += length;
    *remaining -= length;

    return 1;
}

static int append_string(char **output, size_t *remaining, const char *string)
{
    return append_data(output, remaining, string, strlen(string));
}

static int parse_decimal_rounds(const char *text, const char **end, unsigned long *rounds)
{
    unsigned long value;
    const char *p;

    if ((text == NULL) || (end == NULL) || (rounds == NULL)) {
        return 0;
    }

    if ((*text < '0') || (*text > '9')) {
        return 0;
    }

    value = 0UL;
    p = text;

    while ((*p >= '0') && (*p <= '9')) {
        unsigned long digit = (unsigned long)(*p - '0');

        /*
         * Saturate rather than overflowing. Values above the supported
         * maximum will subsequently be clamped.
         */
        if (value > ((SHA512_CRYPT_MAX_ROUNDS - digit) / 10UL)) {
            value = SHA512_CRYPT_MAX_ROUNDS;
            while ((*p >= '0') && (*p <= '9')) {
                ++p;
            }
            break;
        }

        value = (value * 10UL) + digit;
        ++p;
    }

    *end = p;
    *rounds = value;

    return 1;
}


static int parse_setting(const char *setting, const char **salt, size_t *salt_length, unsigned long *rounds, int *rounds_explicit)
{
    const char *p;
    const char *rounds_end;
    size_t length;
    unsigned long requested_rounds;

    if ((setting == NULL) ||
        (salt == NULL) ||
        (salt_length == NULL) ||
        (rounds == NULL) ||
        (rounds_explicit == NULL)) {
        return 0;
    }

    p = setting;

    if (strncmp(p, SHA512_CRYPT_PREFIX, sizeof(SHA512_CRYPT_PREFIX) - 1) == 0) {
        p += sizeof(SHA512_CRYPT_PREFIX) - 1U;
    }

    *rounds = SHA512_CRYPT_DEFAULT_ROUNDS;
    *rounds_explicit = 0;

    if (strncmp(p, SHA512_CRYPT_ROUNDS_PREFIX, sizeof(SHA512_CRYPT_ROUNDS_PREFIX) - 1U) == 0) {
        const char *rounds_text = p + sizeof(SHA512_CRYPT_ROUNDS_PREFIX) - 1;

        if (!parse_decimal_rounds(rounds_text,
                                  &rounds_end,
                                  &requested_rounds)) {
            return 0;
        }

        if (*rounds_end != '$') {
            return 0;
        }

        if (requested_rounds < SHA512_CRYPT_MIN_ROUNDS) {
            requested_rounds = SHA512_CRYPT_MIN_ROUNDS;
        } else if (requested_rounds > SHA512_CRYPT_MAX_ROUNDS) {
            requested_rounds = SHA512_CRYPT_MAX_ROUNDS;
        }

        *rounds = requested_rounds;
        *rounds_explicit = 1;
        p = rounds_end + 1;
    }

    length = 0;

    while ((p[length] != '\0') &&
           (p[length] != '$') &&
           (length < SHA512_CRYPT_MAX_SALT_LENGTH)) {
        ++length;
    }

    /*
     * SHA-crypt salts use the crypt Base64 character set. Reject malformed
     * salts rather than silently accepting arbitrary punctuation.
     */
    for (size_t i = 0U; i < length; ++i) {
        if (strchr(crypt_base64, p[i]) == NULL) {
            return 0;
        }
    }

    if (length == 0U) {
        return 0;
    }

    *salt = p;
    *salt_length = length;

    return 1;
}


int sha512_crypt(const char *password, const char *setting, char *output, size_t output_length)
{
    sha512_ctx_t ctx, altctx;

    uint8_t alternate_result[SHA512_CRYPT_DIGEST_LENGTH];
    uint8_t temporary_result[SHA512_CRYPT_DIGEST_LENGTH];
    uint8_t p_digest[SHA512_CRYPT_DIGEST_LENGTH];
    uint8_t s_digest[SHA512_CRYPT_DIGEST_LENGTH];

    const char *salt;
    size_t password_length;
    size_t salt_length;
    size_t count;
    unsigned long rounds;
    unsigned long round;
    int rounds_explicit;

    char *output_pointer;
    size_t remaining;
    char rounds_string[32];
    int rounds_string_length;
    int success;

    if ((password == NULL) || (setting == NULL) || (output == NULL) || (output_length == 0U)) {
            return 0;
    }

    output[0] = '\0';
    success = 0;

    if (!parse_setting(setting, &salt, &salt_length, &rounds, &rounds_explicit)) {
        return 0;
    }

    password_length = strlen(password);

    /*
     * Digest A starts with:
     *
     *     password || salt
     */
    sha512_init(&ctx);
    sha512_update(&ctx, password, password_length);
    sha512_update(&ctx, salt, salt_length);

    /*
     * Digest B:
     *
     *     SHA512(password || salt || password)
     */
    sha512_init(&altctx);
    sha512_update(&altctx, password, password_length);
    sha512_update(&altctx, salt, salt_length);
    sha512_update(&altctx, password, password_length);
    sha512_final(&altctx, alternate_result);

    /*
     * Append password_length bytes of digest B to digest A.
     */
    sha512_update_repeated_digest(&ctx, alternate_result, password_length);

    /*
     * For each bit in password_length, least-significant bit first:
     *
     *     bit is 1: append digest B
     *     bit is 0: append password
     */
    for (count = password_length; count != 0U; count >>= 1) {
        if ((count & 1) != 0) {
            sha512_update(&ctx, alternate_result, SHA512_CRYPT_DIGEST_LENGTH);
        } else {
            sha512_update(&ctx, password, password_length);
        }
    }

    sha512_final(&ctx, alternate_result);

    /*
     * P digest:
     *
     *     SHA512(password repeated password_length times)
     */
    sha512_init(&altctx);

    for (count = 0U; count < password_length; ++count) {
        sha512_update(&altctx,
                      password,
                      password_length);
    }

    sha512_final(&altctx, p_digest);

    /*
     * S digest:
     *
     *     SHA512(salt repeated 16 + alternate_result[0] times)
     */
    sha512_init(&altctx);

    for (count = 0U;
         count < (size_t)(16U + alternate_result[0]);
         ++count) {
        sha512_update(&altctx, salt, salt_length);
    }

    sha512_final(&altctx, s_digest);

    /*
     * Main SHA-512-crypt rounds.
     *
     * P_bytes means the P digest repeated or truncated to password_length.
     * S_bytes means the S digest repeated or truncated to salt_length.
     */
    for (round = 0UL; round < rounds; ++round) {
        sha512_init(&ctx);

        if ((round & 1UL) != 0UL) {
            sha512_update_repeated_digest(&ctx,
                                          p_digest,
                                          password_length);
        } else {
            sha512_update(&ctx,
                          alternate_result,
                          SHA512_CRYPT_DIGEST_LENGTH);
        }

        if ((round % 3UL) != 0UL) {
            sha512_update_repeated_digest(&ctx,
                                          s_digest,
                                          salt_length);
        }

        if ((round % 7UL) != 0UL) {
            sha512_update_repeated_digest(&ctx,
                                          p_digest,
                                          password_length);
        }

        if ((round & 1UL) != 0UL) {
            sha512_update(&ctx,
                          alternate_result,
                          SHA512_CRYPT_DIGEST_LENGTH);
        } else {
            sha512_update_repeated_digest(&ctx,
                                          p_digest,
                                          password_length);
        }

        sha512_final(&ctx, temporary_result);
        memcpy(alternate_result,
               temporary_result,
               SHA512_CRYPT_DIGEST_LENGTH);
    }

    /*
     * Construct:
     *
     *     $6$[rounds=N$]salt$hash
     */
    output_pointer = output;
    remaining = output_length;

    if (!append_string(&output_pointer, &remaining, SHA512_CRYPT_PREFIX)) {
        goto cleanup;
    }

    if (rounds_explicit) {
        rounds_string_length = snprintf(rounds_string, sizeof(rounds_string), "rounds=%lu$", rounds);

        if ((rounds_string_length < 0) ||
            ((size_t)rounds_string_length >= sizeof(rounds_string))) {
            goto cleanup;
        }

        if (!append_data(&output_pointer, &remaining, rounds_string, (size_t)rounds_string_length)) {
            goto cleanup;
        }
    }

    if (!append_data(&output_pointer, &remaining, salt, salt_length)) {
        goto cleanup;
    }

    if (!append_string(&output_pointer, &remaining, "$")) {
        goto cleanup;
    }

#define ENCODE_24(a, b, c, n)                                           \
    do {                                                                 \
        if (!crypt_base64_from_24(                                       \
                alternate_result[(a)],                                   \
                alternate_result[(b)],                                   \
                alternate_result[(c)],                                   \
                (n),                                                     \
                &output_pointer,                                         \
                &remaining)) {                                           \
            goto cleanup;                                                \
        }                                                                \
    } while (0)

    ENCODE_24(0,  21, 42, 4);
    ENCODE_24(22, 43, 1,  4);
    ENCODE_24(44, 2,  23, 4);
    ENCODE_24(3,  24, 45, 4);
    ENCODE_24(25, 46, 4,  4);
    ENCODE_24(47, 5,  26, 4);
    ENCODE_24(6,  27, 48, 4);
    ENCODE_24(28, 49, 7,  4);
    ENCODE_24(50, 8,  29, 4);
    ENCODE_24(9,  30, 51, 4);
    ENCODE_24(31, 52, 10, 4);
    ENCODE_24(53, 11, 32, 4);
    ENCODE_24(12, 33, 54, 4);
    ENCODE_24(34, 55, 13, 4);
    ENCODE_24(56, 14, 35, 4);
    ENCODE_24(15, 36, 57, 4);
    ENCODE_24(37, 58, 16, 4);
    ENCODE_24(59, 17, 38, 4);
    ENCODE_24(18, 39, 60, 4);
    ENCODE_24(40, 61, 19, 4);
    ENCODE_24(62, 20, 41, 4);

#undef ENCODE_24

    /*
     * Final byte is encoded as:
     *
     *     0, 0, alternate_result[63]
     */
    if (!crypt_base64_from_24(0, 0, alternate_result[63], 2, &output_pointer, &remaining)) {
        goto cleanup;
    }

    if (remaining == 0) {
        goto cleanup;
    }

    *output_pointer = '\0';
    success = 1;

cleanup:
    if (!success) {
        output[0] = '\0';
    }

    secure_clear(alternate_result, sizeof(alternate_result));
    secure_clear(temporary_result, sizeof(temporary_result));
    secure_clear(p_digest, sizeof(p_digest));
    secure_clear(s_digest, sizeof(s_digest));
    secure_clear(&ctx, sizeof(ctx));
    secure_clear(&altctx, sizeof(altctx));
    secure_clear(rounds_string, sizeof(rounds_string));

    return success;
}


/*
 * compare_string_constant_time() - compare two strings with constant time
 * to avoid timing attacks. See:
 *
 *	https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
 */
static int compare_string_constant_time(const char *a, const char *b)
{
    if (a && b) {
        int m = 0;
        volatile int i = 0;
        volatile int j = 0;
        volatile int k = 0;

        while (1) {
            m |= a[i] ^ b[j];

            if (a[i] == '\0')
                break;
                
            i++;

            if (b[j] != '\0')
                j++;
                
            if (b[j] == '\0')
                k++;
        }

        return (m == 0);
        
    } else {
        return 0;
    }
}


/*
 * sha512_crypt_encrypt_password() - encrypt a password
 *
 * This function takes a password, generates a 16-character random salt, encrypts
 * the password with the sha512_crypt() function and salt and outputs the full
 * string in teh form:
 *
 *	$6$abcddefghijklmnop$................................
 *
 * with the salt and encrypted password.
 *
 */
int sha512_crypt_encrypt_password(const char *password, char *output, size_t outlen)
{
    char salt[SHA512_CRYPT_SALT_SIZE+1];
    char buf[40];
    int rc;
    
    sha512_crypt_salt(salt);
    
    sprintf(buf, "%s%s$", SHA512_CRYPT_PREFIX, salt);    
    
    rc = sha512_crypt(password, buf, output, outlen);

    return rc;
}


/*
 * sha512_crypt_verify_password() - Verify a password
 *
 * This function verifies the user supplied password against the $6$ sha512_crypt
 * password in 'hash' and returns zero (invalid) or one (valid).
 *
 */
int sha512_crypt_verify_password(const char *password, const char *hash)
{
    char calc[SHA512_CRYPT_MAX_OUTPUT_LENGTH];
    int valid;

    if ((password == NULL) || (hash == NULL)) {
        return 0;
    }

    if (strncmp(hash, SHA512_CRYPT_PREFIX, sizeof(SHA512_CRYPT_PREFIX) - 1) != 0) {
        return 0;
    }

    if (!sha512_crypt(password, hash, calc, sizeof(calc))) {
        return 0;
    }

    valid = compare_string_constant_time(calc, hash);
    secure_clear(calc, sizeof(calc));

    return valid;
}
