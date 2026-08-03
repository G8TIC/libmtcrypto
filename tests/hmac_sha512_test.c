#include <stdio.h>
#include <string.h>

#include "hmac_sha512.h"


/* helper: bytes → lowercase hex string */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; ++i)
        sprintf(&out[i * 2], "%02x", in[i]);
    out[len * 2] = '\0';
}

/*
 * Known-answer test vectors for HMAC-SHA512
 * From RFC 4231
 */
int hmac_sha512_selftest(void)
{
    struct {
        const uint8_t *key;
        size_t key_len;
        const uint8_t *data;
        size_t data_len;
        const char *expected;
    } tests[] = {
        {
            (const uint8_t *)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                             "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            20,
            (const uint8_t *)"Hi There", 8,
            "87aa7cdea5ef619d4ff0b4241a1d6cb0"
            "2379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4"
            "be9d914eeb61f1702e696c203a126854"
        },
        {
            (const uint8_t *)"Jefe", 4,
            (const uint8_t *)"what do ya want for nothing?", 28,
            "164b7a7bfcf819e2e395fbe73b56e0a3"
            "87bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fd"
            "caeab1a34d4a6b4b636e070a38bce737"
        },
        {
            (const uint8_t *)
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
            20,
            (const uint8_t *)
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
            50,
            "fa73b0089d56a284efb0f0756c890be9"
            "b1b5dbdd8ee81a3655f83e33b2279d39"
            "bf3e848279a722c806b485a47e67c807"
            "b946a337bee8942674278859e13292fb"
        },
    };

    uint8_t digest[HMAC_SHA512_DIGEST_SIZE];
    char hex[HMAC_SHA512_DIGEST_SIZE * 2 + 1];
    int fails = 0;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        hmac_sha512(digest,
                    tests[i].key, tests[i].key_len,
                    tests[i].data, tests[i].data_len);
        bytes_to_hex(digest, HMAC_SHA512_DIGEST_SIZE, hex);
        if (strcmp(hex, tests[i].expected) != 0) {
            printf("HMAC-SHA512 selftest %zu failed\nExpected: %s\nGot:      %s\n",
                   i + 1, tests[i].expected, hex);
            fails++;
        }
    }

    if (fails == 0) {
        printf("HMAC-SHA512 selftest passed (%zu tests)\n",
               sizeof(tests)/sizeof(tests[0]));
    }
    return fails ? 1 : 0;
}





int main(void)
{
    return hmac_sha512_selftest();
}
