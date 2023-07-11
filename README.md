# totp
A program to generate 6 digit TOTP codes like Google Authenticator, and the totp.hpp is a header only library without any extra dependency .

This program implements the "TOTP: Time-Based One-Time Password Algorithm" RFC 6238 to generate 6 digit codes for Multi Factor Authentication, for instance on Amazon AWS.

The implementation of the HMAC-SHA1 hashing is borrowed from the GPL3-licensed project https://github.com/cantora/avr-crypto-lib/

## How to build
Run visual studio build.

## How to use it
```
Usage: totp --key=KEY

Given a base32 secret key, prints the corresponding valid 6 digit time-based one time password (TOTP)
as specified by RFC 6238.

  KEY:      base32 encoded value representing the secret
  --key:    if this option is provided, the output will be in the parsing-friendly
            format XXXXXX:YY where XXXXXX is the code and YY is the remaining lifetime of the
            code given in seconds. Otherwise, prints the results in a more human-friendly way.
```

Examples:

```
$ ./totp --key=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
TOTP = 739991:09

```

## To-do

support interval parameter
