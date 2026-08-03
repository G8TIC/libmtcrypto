
#include <stddef.h>
#include <stdint.h>

#include "secure.h"


/*
 * secure_clear() - clear sensitive data
 *
 * This function is a replacement for memset(data, 0, len) which is optimised out
 * by some compilers when they detect that memory is bring written to but not
 * subsequently read.
 *
 * We need to be able to zeroise memory after use with senstive information like
 * key data, hashes and passwords.
 *
 * This routine uses a volatile pointer which should prevent the compiler's optimiser
 * from removing the memory writes because the memory is not subsequently read.
 */
void secure_clear(void *data, size_t len)
{
        if (data) {
                volatile uint8_t *p = data;

                while (len) {
                        *p++ = 0;
                        --len;
                }
        }
}
