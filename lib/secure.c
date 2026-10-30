/*
 * secure.c -- Memory security functions
 * Author: Mike Tubby G8TIC mike@tubby.org
 */

#include <stddef.h>
#include <stdint.h>

#include "secure.h"

/*
 * secure_clear() - clear sensitive data
 *
 * This function is a replacement for memset(data, 0, len) that can optimised
 * out by some compilers when they detect that memory is being written to but
 * not subsequently read.
 *
 * We need to be able to zeroise memory after use that contains senstive
 * information like key material, hashes and passwords.
 *
 * This routine uses a volatile pointer which should prevent the compiler's
 * optimiser from removing the memory writes because the memory is not
 * subsequently read.
 *
 */
void secure_clear(void *data, size_t len)
{
        if (data && len) {
                volatile uint8_t *p = data;

                while (len) {
                        *p++ = 0;
                        --len;
                }
        }
}
