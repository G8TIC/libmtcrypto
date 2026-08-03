#include <stdio.h>
#include <string.h>

#include "hmac_sha256.h"


/* simple helper: convert bytes to lowercase hex string */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    for (size_t i = 0; i < len; ++i)
        sprintf(&hex[i * 2], "%02x", bytes[i]);
    hex[len * 2] = '\0';
}

/*
 * Self-test based on RFC 4231 test vectors
 */
int hmac_sha256_selftest(void)
{
    struct {
        const uint8_t *key;
        size_t key_len;
        const uint8_t *data;
        size_t data_len;
        const char *expected_hex;
    } tests[] = {
        /* Test Case 1 */
        { (const uint8_t *)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
          20,
          (const uint8_t *)"Hi There", 8,
          "b0344c61d8db38535ca8afceaf0bf12b"
          "881dc200c9833da726e9376c2e32cff7" },
        /* Test Case 2 */
        { (const uint8_t *)"Jefe", 4,
          (const uint8_t *)"what do ya want for nothing?", 28,
          "5bdcc146bf60754e6a042426089575c7"
          "5a003f089d2739839dec58b964ec3843" },
        /* Test Case 3 */
        { (const uint8_t *)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
          20,
          (const uint8_t *)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
          50,
          "773ea91e36800e46854db8ebd09181a7"
          "2959098b3ef8c122d9635514ced565fe" }
    };

    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE * 2 + 1];
    int failures = 0;

    for (size_t t = 0; t < sizeof(tests) / sizeof(tests[0]); ++t) {
    
        hmac_sha256(digest, tests[t].key, tests[t].key_len, tests[t].data, tests[t].data_len);
    
        bytes_to_hex(digest, SHA256_DIGEST_SIZE, hex);
    
        if (strcmp(hex, tests[t].expected_hex) != 0) {
            printf("HMAC-SHA256 selftest %zu failed:\n expected %s\n got      %s\n",
                   t + 1, tests[t].expected_hex, hex);
            failures++;
        }
    }

    if (failures == 0)
        printf("HMAC-SHA256 selftest passed (%zu tests)\n",
               sizeof(tests) / sizeof(tests[0]));

    return failures ? 1 : 0;
}



int main(void)
{
    uint8_t mac[SHA256_DIGEST_SIZE];
    const uint8_t key[] = "key";
    const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

    hmac_sha256(mac, key, 3, msg, sizeof(msg) - 1);

    for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i)
        printf("%02x", mac[i]);
    printf("\n");

    /* Run built-in RFC 4231 test vectors */
    return hmac_sha256_selftest();
}
