/**
 * Copyright (C) 2019 - gurushida
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "base32.h"
#include "totp.h"


int main(int argc, char* argv[]) {
    const char* optstring = "r";
    const struct option lopts[] = {
        { "raw", no_argument, NULL, 'r' },
        { NULL, no_argument, NULL, 0 }
    };

    char raw = 0;

    int val, index = -1;
    while (EOF != (val = getopt_long(argc, argv, optstring, lopts, &index))) {
        switch (val) {
            case 'r': raw = 1; break;
        }
        index = -1;
    }

    if (optind == argc) {
        printf("Usage: %s [-r|--raw] KEY\n", argv[0]);
        printf("\n");
        printf("Given a base32 secret key, prints the corresponding valid 6 digit time-based one time password (TOTP)\n");
        printf("as specified by RFC 6238.\n");
        printf("\n");
        printf("  KEY:      base32 encoded value representing the secret\n");
        printf("  -r|--raw: if this option is provided, the output will be in the parsing-friendly\n");
        printf("            format XXXXXX:YY where XXXXXX is the code and YY is the remaining lifetime of the\n");
        printf("            code given in seconds. Otherwise, prints the results in a more human-friendly way.\n");
        printf("\n");
        return 0;
    }

    char* base32_key = argv[optind];

    uint8_t* key;
    int size_key = decode_base32(base32_key, &key);
    if (size_key == -1) {
        fprintf(stderr, "The given secret '%s' is not a valid base32 encoded value\n", base32_key);
        exit(1);
    }
    if (size_key == -2) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    char code[7];
    int code_lifetime = get_totp(key, 20, code);

    if (raw) {
        printf("%s:%02d\n", code, code_lifetime);
    } else {
        printf("TOTP = %s valid for %02d second%s\n", code, code_lifetime, (code_lifetime > 1) ? "s" : "");
    }
    return 0;
}
