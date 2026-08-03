#include "sha1.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void print_digest(const uint8_t digest[SHA1_DIGEST_SIZE])
{
    size_t index;

    for (index = 0U; index < SHA1_DIGEST_SIZE; ++index) {
        printf("%02" PRIx8, digest[index]);
    }

    putchar('\n');
}

int main(void)
{
    static const char message[] = "abc";
    uint8_t digest[SHA1_DIGEST_SIZE];
    sha1_ctx_t ctx;

    /*
     * Single-call interface.
     *
     * Expected:
     * a9993e364706816aba3e25717850c26c9cd0d89d
     */
    sha1(digest, message, strlen(message));
    print_digest(digest);

    /*
     * Incremental interface. This must produce the same digest.
     */
    sha1_init(&ctx);
    sha1_update(&ctx, "a", 1U);
    sha1_update(&ctx, "b", 1U);
    sha1_update(&ctx, "c", 1U);
    sha1_final(&ctx, digest);
    print_digest(digest);

    /*
     * Empty input.
     *
     * Expected:
     * da39a3ee5e6b4b0d3255bfef95601890afd80709
     */
    sha1(digest, NULL, 0U);
    print_digest(digest);

    return 0;
}

