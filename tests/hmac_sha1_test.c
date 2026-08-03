#include <stdio.h>
#include <string.h>

#include "hmac_sha1.h"


/*
 * bytes_to_hex() - convert bytes to a lowercase hexadecimal string
 *
 * hex must point to a buffer containing at least (len * 2) + 1 bytes.
 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
        size_t i;

        for (i = 0U; i < len; ++i)
                (void)sprintf(&hex[i * 2U], "%02x", bytes[i]);

        hex[len * 2U] = '\0';
}


/*
 * hmac_sha1_selftest() - run HMAC-SHA-1 RFC 2202 test vectors
 *
 * Each vector is tested using both:
 *
 *     1. The one-shot hmac_sha1() function.
 *     2. The streaming init/update/final API.
 *
 * Returns zero if all tests pass, otherwise returns one.
 */
int hmac_sha1_selftest(void)
{
        static const uint8_t test_1_key[] = {
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        };

        static const uint8_t test_1_data[] = "Hi There";

        static const uint8_t test_2_key[] = "Jefe";

        static const uint8_t test_2_data[] =
                "what do ya want for nothing?";

        static const uint8_t test_3_key[] = {
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa
        };

        static const uint8_t test_3_data[] = {
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd
        };

        static const struct {
                const uint8_t *key;
                size_t key_len;
                const uint8_t *data;
                size_t data_len;
                const char *expected_hex;
        } tests[] = {
                {
                        test_1_key,
                        sizeof(test_1_key),
                        test_1_data,
                        sizeof(test_1_data) - 1U,
                        "b617318655057264e28bc0b6fb378c8ef146be00"
                },
                {
                        test_2_key,
                        sizeof(test_2_key) - 1U,
                        test_2_data,
                        sizeof(test_2_data) - 1U,
                        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
                },
                {
                        test_3_key,
                        sizeof(test_3_key),
                        test_3_data,
                        sizeof(test_3_data),
                        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
                }
        };

        uint8_t digest[HMAC_SHA1_DIGEST_SIZE];
        char hex[(HMAC_SHA1_DIGEST_SIZE * 2U) + 1U];
        size_t test_count;
        size_t t;
        int failures = 0;

        test_count = sizeof(tests) / sizeof(tests[0]);

        for (t = 0U; t < test_count; ++t) {
                hmac_sha1(digest,
                          tests[t].key,
                          tests[t].key_len,
                          tests[t].data,
                          tests[t].data_len);

                bytes_to_hex(digest, sizeof(digest), hex);

                if (strcmp(hex, tests[t].expected_hex) != 0) {
                        printf("HMAC-SHA1 one-shot selftest %zu failed:\n"
                               " expected %s\n"
                               " got      %s\n",
                               t + 1U,
                               tests[t].expected_hex,
                               hex);

                        ++failures;
                }
        }

        /*
         * Repeat the tests using the streaming API. Split each input into
         * three sections, including cases where one or more sections may
         * contain zero bytes.
         */
        for (t = 0U; t < test_count; ++t) {
                hmac_sha1_ctx_t ctx;
                size_t first_len;
                size_t second_len;
                size_t third_len;

                first_len = tests[t].data_len / 3U;
                second_len = tests[t].data_len / 3U;
                third_len = tests[t].data_len -
                            first_len -
                            second_len;

                hmac_sha1_init(&ctx,
                               tests[t].key,
                               tests[t].key_len);

                hmac_sha1_update(&ctx,
                                 tests[t].data,
                                 first_len);

                hmac_sha1_update(&ctx,
                                 tests[t].data + first_len,
                                 second_len);

                hmac_sha1_update(&ctx,
                                 tests[t].data + first_len + second_len,
                                 third_len);

                hmac_sha1_final(&ctx, digest);

                bytes_to_hex(digest, sizeof(digest), hex);

                if (strcmp(hex, tests[t].expected_hex) != 0) {
                        printf("HMAC-SHA1 streaming selftest %zu failed:\n"
                               " expected %s\n"
                               " got      %s\n",
                               t + 1U,
                               tests[t].expected_hex,
                               hex);

                        ++failures;
                }
        }

        if (failures == 0) {
                printf("HMAC-SHA1 selftest passed "
                       "(%zu vectors, one-shot and streaming)\n",
                       test_count);
        } else {
                printf("HMAC-SHA1 selftest failed "
                       "(%d failure%s)\n",
                       failures,
                       failures == 1 ? "" : "s");
        }

        return failures == 0 ? 0 : 1;
}


int main(void)
{
        static const uint8_t key[] = "key";
        static const uint8_t message[] =
                "The quick brown fox jumps over the lazy dog";

        static const char expected_hex[] =
                "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";

        uint8_t mac[HMAC_SHA1_DIGEST_SIZE];
        char hex[(HMAC_SHA1_DIGEST_SIZE * 2U) + 1U];

        hmac_sha1(mac,
                  key,
                  sizeof(key) - 1U,
                  message,
                  sizeof(message) - 1U);

        bytes_to_hex(mac, sizeof(mac), hex);

        printf("HMAC-SHA1 example:\n");
        printf(" expected %s\n", expected_hex);
        printf(" got      %s\n", hex);

        if (strcmp(hex, expected_hex) != 0) {
                printf("HMAC-SHA1 example failed\n");
                return 1;
        }

        return hmac_sha1_selftest();
}

