#ifndef _BASE32_H
#define _BASE32_H

#include <stddef.h>
#include <stdint.h>

/*
 * Decode an RFC 4648 Base32 string.
 *
 * The decoder:
 *
 *   - accepts upper- or lower-case letters;
 *   - accepts optional '=' padding;
 *   - ignores spaces, tabs, CR, LF and hyphens;
 *   - returns 1 on success and 0 on failure.
 *
 * output_length receives the number of decoded bytes.
 */
int base32_decode(const char *input, uint8_t *output, size_t output_capacity, size_t *output_length);

/*
 * Encode binary data using RFC 4648 Base32.
 *
 * The encoded output is upper-case and includes '=' padding.
 * The output is always null terminated on success.
 *
 * output_length receives the number of encoded characters,
 * excluding the terminating null byte.
 *
 * Returns 1 on success and 0 on failure.
 */
int base32_encode(const uint8_t *input, size_t input_length, char *output, size_t output_capacity, size_t *output_length);

#endif
