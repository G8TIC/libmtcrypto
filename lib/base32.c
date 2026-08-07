/*
 * base32.c -- encode and decode Base32 strings
 */

#include "base32.h"

#include <stddef.h>
#include <stdint.h>

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


static int base32_character_value(unsigned char character)
{
    if (character >= 'A' && character <= 'Z') {
        return (int)(character - 'A');
    }

    if (character >= 'a' && character <= 'z') {
        return (int)(character - 'a');
    }

    if (character >= '2' && character <= '7') {
        return (int)(character - '2') + 26;
    }

    return -1;
}


static int base32_is_ignored_character(unsigned char character)
{
    if (character == ' ' ||
        character == '\t' ||
        character == '\r' ||
        character == '\n' ||
        character == '-') {
        return 1;
    }

    return 0;
}


int base32_decode(const char *input, uint8_t *output, size_t output_capacity, size_t *output_length)
{
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    size_t produced = 0;
    int padding_seen = 0;

    if (input == NULL || output == NULL || output_length == NULL) {
        return 0;
    }

    *output_length = 0;

    while (*input != '\0') {
        unsigned char character = (unsigned char)*input++;
        int value;

        if (base32_is_ignored_character(character)) {
            continue;
        }

        if (character == '=') {
            padding_seen = 1;
            continue;
        }

        if (padding_seen) {
            return 0;
        }

        value = base32_character_value(character);

        if (value < 0) {
            return 0;
        }

        accumulator = (accumulator << 5) | (uint32_t)value;
        bit_count += 5;

        while (bit_count >= 8) {
            bit_count -= 8;

            if (produced >= output_capacity) {
                return 0;
            }

            output[produced++] = (uint8_t)(accumulator >> bit_count);

            if (bit_count == 0) {
                accumulator = 0;
            } else {
                accumulator &= ((uint32_t)1 << bit_count) - 1;
            }
        }
    }

    if (produced == 0) {
        return 0;
    }

    /*
     * Any unused bits in the final Base32 symbol must be zero.
     */
    if (bit_count != 0 && accumulator != 0) {
        return 0;
    }

    *output_length = produced;

    return 1;
}


int base32_encode(const uint8_t *input, size_t input_length, char *output, size_t output_capacity, size_t *output_length)
{
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    size_t produced = 0;
    size_t input_index;
    size_t unpadded_length;
    size_t padded_length;

    if (input == NULL || output == NULL || output_length == NULL) {
        return 0;
    }

    *output_length = 0;

    if (input_length == 0) {
        if (output_capacity < 1) {
            return 0;
        }

        output[0] = '\0';
        return 1;
    }

    unpadded_length = (input_length * 8 + 4) / 5;
    padded_length = ((unpadded_length + 7) / 8) * 8;

    if (output_capacity < padded_length + 1) {
        return 0;
    }

    for (input_index = 0; input_index < input_length; ++input_index) {
        accumulator = (accumulator << 8) | input[input_index];
        bit_count += 8;

        while (bit_count >= 5) {
            bit_count -= 5;
            output[produced++] = base32_alphabet[(accumulator >> bit_count) & 0x1f];

            if (bit_count == 0) {
                accumulator = 0;
            } else {
                accumulator &= ((uint32_t)1 << bit_count) - 1;
            }
        }
    }

    if (bit_count != 0) {
        output[produced++] = base32_alphabet[(accumulator << (5 - bit_count)) & 0x1f];
    }

    while (produced < padded_length) {
        output[produced++] = '=';
    }

    output[produced] = '\0';
    *output_length = produced;

    return 1;
}
