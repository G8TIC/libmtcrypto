#include <stdio.h>
#include <string.h>

#include "sha512.h"


/* helper: convert bytes to lowercase hex string */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; ++i) {
        sprintf(&out[i * 2], "%02x", in[i]);
    }
    out[len * 2] = '\0';
}



/* known-answer self-test (FIPS 180-4 vectors) */
int sha512_selftest(void)
{
    struct {
        const char *msg;
        const char *expected;
    } tests[] = {
        {
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        },
        {
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        },
        {
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        }
    };

    uint8_t digest[SHA512_DIGEST_SIZE];
    char hex[SHA512_DIGEST_SIZE * 2 + 1];
    int fails = 0;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        sha512(digest, (const uint8_t *)tests[i].msg, strlen(tests[i].msg));
        bytes_to_hex(digest, SHA512_DIGEST_SIZE, hex);
        if (strcmp(hex, tests[i].expected) != 0) {
            printf("SHA512 selftest %zu failed\nExpected: %s\nGot:      %s\n",
                   i + 1, tests[i].expected, hex);
            fails++;
        }
    }

    if (fails == 0) {
        printf("SHA512 selftest passed (%zu tests)\n", sizeof(tests)/sizeof(tests[0]));
    }
    return fails ? 1 : 0;
}





int main(void)
{
    /* Run built-in known-answer test */
    return sha512_selftest();
}

