# libmtcrypto - Light weight crypto routines for embedded systems and small programs.

## Introduction
A collection of hash functions, HMAC functions and ciphers implemented in
procedural C (C11 standard) with simple APIs/calling conventions and small
foot prints suitable for embedded systems like STM32, ESP32 and Linux
daemons where dependencies on libraries like OpenSSL is unwarranted or
undesireable.

## Background

I have been using SHA1, SHA256 and SHA512 in embedded systems they have existed
but with source code that was complex reference code, code borrowed from crypto
libraries, or versions found on the internet with questional parentage such as
those where copyright is claimed by Apple or Google.

I decided that I needed to fix this ...

## Goals and objectives

I decided that for embedded systems I needed my own implementation of SHA1,
SHA256 and SHA512 along with their HMAC equivalents, that:

* use modern and clean C code
* are designed for standalone use
* are portable across a wide range of systems
* are compiler agnostic
* have simple API calling conventions
* is easy to read, understand and maintain
* includes unit tests against NIST test vectors
* employs a permissive license


### Modern and clean code

The routes here were Written to be modern and clean using procedural C to the C11 standard.

### Standalone

The routines here are complete, standalone, and makes no use of libraries or third-party code.

### Portable

As the code is written in plain procedural C it should compile and work on a wide range of systems.

To date its been used on 64-bit AMD (x86), 32-bit ARM and 64-bit ARM.

Note: The code has only be developed and tested on Little Endian machines and is not expected to work on Big Endian
platforms without further modification.

### Compiler agnostic

While the code was developed using GCC it uses only standard C11 subset of
the language so it should work on any C11 compliant compiler.

### Simple APIs

While you can delve in to the innards and do things in parts (i.e. streaming
mode), in most cases you just want the single shot function, for example:
```
sha256(uint8_t *out, void *data, size_t length)
```

### Unit tests

Each module includes a test harness with suitable test vectors - in many
cases the NIST test vectors.

All modules can be tested using the unit_tests.sh script.


## Organisation

This repository has three directories:

lib -- contains the source code files and a Makefile to build the library

include -- contains the header files to include in your projects

tests -- a set of simple test programs and unit tests



### License

This code is licensed under the MIT License.  See 'LICENSE' for details.
