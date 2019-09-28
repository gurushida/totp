totp: main.c totp.c base32.c sha1.c hmac-sha1.c
	$(CC) main.c totp.c base32.c sha1.c hmac-sha1.c -o totp -Wall -Wextra -pedantic -std=c99

install: totp
	cp totp /usr/local/bin/

