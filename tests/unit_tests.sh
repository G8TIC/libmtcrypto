#!/bin/bash
#
# unit_tests.sh -- Unit tests for SHA256, SHA512, HMAC-SHA256 and HMAC-SHA512
#
# SPDX-License-Identifier: MIT
# Copyright (C) 2025 Mike Tubby G8TIC mike@tubby.org and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
#

echo "Unit tests for SHA1, HMAC-SHA1, SHA256, HMAC-SHA256, SHA512 and HMAC-SHA512"

echo ""
echo "Testing SHA1 ..."
gcc -Wall -o sha1_test sha1_test.c -I../include -L ../lib/ -lmtcrypto
./sha1_test

echo ""
echo "Testing HMAC-SHA1 ..."
gcc -Wall -o hmac_sha1_test hmac_sha1_test.c -I../include -L ../lib/ -lmtcrypto
./hmac_sha1_test

echo ""
echo "Testing SHA256 ..."
gcc -Wall -o sha256_test sha256_test.c -I../include -L ../lib/ -lmtcrypto
./sha256_test

echo ""
echo "Testing HMAC-SHA256 ..."
gcc -Wall -o hmac_sha256_test hmac_sha256_test.c -I../include -L ../lib/ -lmtcrypto
./hmac_sha256_test

echo ""
echo "Testing SHA512 ..."
gcc -Wall -o sha512_test sha512_test.c -I../include -L ../lib/ -lmtcrypto
./sha512_test

echo ""
echo "Testing HMAC-SHA512 ..."
gcc -Wall -o hmac_sha512_test hmac_sha512_test.c -I../include -L ../lib/ -lmtcrypto
./hmac_sha512_test

echo ""
echo "Testing SHA512-CRYPT ..."
gcc -Wall -o sha512_crypt_test sha512_crypt_test.c -I../include -L ../lib/ -lmtcrypto
./sha512_crypt_test

echo ""
echo "Testing TOTP authentication codes ..."
gcc -Wall -o totp_test totp_test.c -I../include -L ../lib/ -lmtcrypto
./totp_test



