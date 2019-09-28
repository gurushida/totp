# totp
A C program to generate 6 digit TOTP codes like Google Authenticator.

This program implements the "TOTP: Time-Based One-Time Password Algorithm" RFC 6238 to generate 6 digit codes for Multi Factor Authentication, for instance on Amazon AWS.

The implementation of the HMAC-SHA1 hashing is borrowed from the GPL3-licensed project https://github.com/cantora/avr-crypto-lib/

## How to build
Run `make`.
Run `make install` to install the executable `totp` in `/usr/local/bin`

## How to use it
```
Usage: totp [-r|--raw] KEY

Given a base32 secret key, prints the corresponding valid 6 digit time-based one time password (TOTP)
as specified by RFC 6238.

  KEY:      base32 encoded value representing the secret
  -r|--raw: if this option is provided, the output will be in the parsing-friendly
            format XXXXXX:YY where XXXXXX is the code and YY is the remaining lifetime of the
            code given in seconds. Otherwise, prints the results in a more human-friendly way.
```

Examples:

```
$ ./totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
TOTP = 675249 valid for 03 seconds

$ ./totp --raw GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
675249:03
```
