/*
 * totp_auth.h -- Time-based OTP token authentication to RFC 6283
 * Copyright (C) 2026 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 *
 * USAGE
 *
 * To authenticate a user token, call:
 *
 *	totp_auth(const char *secret, uint32_t user_code)
 *
 * Where:
 *
 * 	secret: is the Base32-encoded secret string
 *
 *	token: is the user provided token (number)
 *
 *
 * This implementation uses a 30-second period and two periods on either side
 * are accepted, giving a five-period validation window.
 *
 * Returns:
 *
 *   1: authentication succeeded
 *   0:  authentication failed
 *
 */

#ifndef _TOTP_AUTH_H
#define _TOTP_AUTH_H

#include <stdint.h>
#include <time.h>

int totp_auth_at(const char *secret, uint32_t token, time_t now);	/* for testing only!! */
int totp_auth(const char *secret, uint32_t token);			/* for production use */

#endif
