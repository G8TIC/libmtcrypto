
CC      = clang
AR      ?= ar

CPPFLAGS = -I../include -DLINUX
CFLAGS   = -Wall -Wextra -Wpedantic -O2
DEPFLAGS = -MMD -MP

LIBRARY  = libmtcrypto.a

SOURCES  = sha1.c sha256.c sha512.c hmac_sha1.c hmac_sha256.c hmac_sha512.c sha512_crypt.c secure.c base32.c totp_auth.c

OBJECTS  = $(SOURCES:.c=.o)
DEPFILES = $(OBJECTS:.o=.d)

.PHONY: all clean

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(DEPFILES) $(LIBRARY)

-include $(DEPFILES)
