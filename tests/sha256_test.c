#include <stdio.h>
#include <string.h>

#include "sha256.h"


/*
 * sha256_selftest() - perform verification using NIST examples
 */
int sha256_selftest(void)
{
    struct {
        const char *msg;
        const char *expected_hex;
    } tests[] = {
        { "abc",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" }
    };

    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE*2+1];
    int failures = 0;

    for (size_t t = 0; t < sizeof(tests)/sizeof(tests[0]); ++t) {
        sha256(digest, (const uint8_t*)tests[t].msg, strlen(tests[t].msg));
        for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i)
            sprintf(&hex[i*2], "%02x", digest[i]);
        hex[SHA256_DIGEST_SIZE*2] = '\0';

        if (strcmp(hex, tests[t].expected_hex) != 0) {
            printf("SHA256 selftest %zu failed:\n expected %s\n got      %s\n",
                   t, tests[t].expected_hex, hex);
            failures++;
        }
    }

    if (failures == 0)
        printf("SHA256 selftest passed (%zu tests)\n", sizeof(tests)/sizeof(tests[0]));
    return failures ? 1 : 0;
}




int main(void)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(digest, (const uint8_t*)"abc", 3);

    for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i)
        printf("%02x", digest[i]);
    printf("\n");

    /* Run built-in known-answer test */
    return sha256_selftest();
}
