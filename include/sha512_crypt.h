#ifndef _SHA512_CRYPT_H
#define _SHA512_CRYPT_H

#include <stdint.h>
#include <stddef.h>


/*
 * Longest normal result:
 *
 * "$6$"                         3
 * "rounds=999999999$"          17
 * salt                         16
 * "$"                           1
 * encoded hash                 86
 * NUL                           1
 *
 * Total                        124
 */
#define SHA512_CRYPT_MAX_OUTPUT_LENGTH	124
#define SHA512_CRYPT_SALT_SIZE		16

int sha512_crypt_salt(char out[SHA512_CRYPT_SALT_SIZE+1]);
int sha512_crypt(const char *password, const char *setting, char *output, size_t output_length);
int sha512_crypt_encrypt_password(const char *password, char *output, size_t output_length);
int sha512_crypt_verify_password(const char *password, const char *stored_hash);

#endif


