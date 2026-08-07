/*
 * totp_auth.h -- Authenticate a six-digit RFC 6238 TOTP value.
 *
 * secret must be an RFC 4648 Base32-encoded secret.
 *
 * Leading zeroes in the displayed value are not represented by
 * user_code. For example, the displayed value 001234 is supplied
 * as the integer 1234.
 *
 * The current 30-second period and two periods on either side are
 * accepted, giving a five-period validation window.
 *
 * Returns:
 *
 *   1  authentication succeeded
 *   0  authentication failed
 */

#ifndef _TOTP_AUTH_H
#define _TOTP_AUTH_H

#include <stdint.h>
#include <time.h>

int totp_auth_at(const char *secret, uint32_t user_code, time_t now);	/* for testing */
int totp_auth(const char *secret, uint32_t user_code);			/* for production */

#endif
