# totp
A C program to generate 6 digit TOTP codes like Google Authenticator.

This program implements the "TOTP: Time-Based One-Time Password Algorithm" RFC 6238 to generate 6 digit codes for Multi Factor Authentication, for instance on Amazon AWS.

The implementation of the HMAC-SHA1 hashing is borrowed from the GPL3-licensed project https://github.com/cantora/avr-crypto-lib/
