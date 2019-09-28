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
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hmac-sha1.h"


/**
 * Returns the number of periods of 30 seconds since the beginning of the
 * Unix Epoch as a 8 byte value.
 */
static void get_half_minutes_elapsed(u_int8_t* output) {
    time_t now = time(NULL);
    time_t half_minutes = now / 30;
    int n = sizeof(time_t);
    memset(output, 0, 8);
    for (int i = 0 ; i < n ; i++) {
        output[7 - i] = half_minutes & 0xFF;
        half_minutes = half_minutes >> 8;
    }
}


int get_totp(u_int8_t* secret, size_t secret_size, char* code) {
    unsigned char half_minutes[8];
    get_half_minutes_elapsed(half_minutes);

    u_int8_t hash[20];

    // The hmac_sha1 expects sizes in bits, not bytes, hence the x8
    hmac_sha1(hash, secret, secret_size * 8, half_minutes, 8 * 8);

    int offset = hash[19] & 0xf;
    u_int32_t binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

    int otp = binary % 1000000;
    for (int i = 0 ; i < 6 ; i++) {
        code[5 - i] = '0' + (otp % 10);
        otp = otp / 10;
    }
    code[6] = '\0';

    return 30 - (time(NULL) % 30);
}

