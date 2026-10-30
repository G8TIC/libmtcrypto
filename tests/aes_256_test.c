/* aes_256_test.c -- FIPS 197 and SP 800-38A AES-256 vectors. SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_256.h"

static unsigned int checks;
static void check(int value, const char *label)
{
	++checks;
	if (!value) {
		fprintf(stderr, "FAIL: %s\n", label);
		exit(EXIT_FAILURE);
	}
}

static void decode(uint8_t *out, const char *hex)
{
	while (*hex) {
		unsigned int byte;

		check(sscanf(hex, "%2x", &byte) == 1, "hex fixture");
		*out++ = (uint8_t)byte;
		hex += 2;
	}
}

int main(void)
{
	static const char *plain[] = {
		"00112233445566778899aabbccddeeff", "6bc1bee22e409f96e93d7e117393172a",
		"ae2d8a571e03ac9c9eb76fac45af8e51", "30c81c46a35ce411e5fbc1191a0a52ef", "f69f2445df4f9b17ad2b417be66c3710"
	};
	static const char *cipher[] = {
		"8ea2b7ca516745bfeafc49904b496089", "f3eed1bdb5d2a03c064b5a7e3db181f8",
		"591ccb10d410ed26dc5ba74a31362870", "b6ed21b99ca6f4f9f153e7b1beafed1d", "23304b7a39f9f3ff067d8d8f9e24ecc7"
	};
	uint8_t key[32], input[16], expected[16], output[16], recovered[16];
	aes_256_ctx_t ctx = {0};

	for (size_t i = 0; i < 5; ++i) {
		decode(key, i ? "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" :
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		decode(input, plain[i]);
		decode(expected, cipher[i]);
		check(aes_256_init(&ctx, key), "expand key");
		check(aes_256_encrypt_block(output, input, &ctx), "encrypt block");
		check(!memcmp(output, expected, 16), "published encryption vector");
		check(aes_256_decrypt_block(recovered, expected, &ctx), "decrypt block");
		check(!memcmp(recovered, input, 16), "published decryption vector");
		check(aes_256_encrypt(output, input, key) && !memcmp(output, expected, 16), "single-shot encrypt");
		check(aes_256_decrypt(output, expected, key) && !memcmp(output, input, 16), "single-shot decrypt");
		memcpy(output, input, 16);
		check(aes_256_encrypt_block(output, output, &ctx) && !memcmp(output, expected, 16), "in-place encrypt");
		check(aes_256_decrypt_block(output, output, &ctx) && !memcmp(output, input, 16), "in-place decrypt");
	}
	check(!aes_256_init(NULL, key), "NULL context");
	check(!aes_256_init(&ctx, NULL), "NULL key");
	check(!aes_256_encrypt_block(NULL, input, &ctx), "NULL output");
	check(!aes_256_decrypt_block(output, NULL, &ctx), "NULL input");
	aes_256_clear(&ctx);
	for (size_t i = 0; i < sizeof(ctx); ++i) {
		check(((const uint8_t *)&ctx)[i] == 0, "context securely cleared");
	}
	memset(output, 0xa5, sizeof(output));
	check(!aes_256_encrypt_block(output, input, &ctx), "cleared context rejected");
	check(output[0] == 0xa5 && output[15] == 0xa5, "invalid context leaves output untouched");
	aes_256_clear(NULL);
	printf("PASS: %u AES-256 checks\n", checks);
	return EXIT_SUCCESS;
}
