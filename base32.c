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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char* valid_base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


int decode_base32(char* msg, uint8_t* *output) {
    if (msg == NULL || strlen(msg) == 0) {
        return -1;
    }
    *output = (uint8_t*)malloc(sizeof(uint8_t) * strlen(msg));
    if (!*output) {
        return -2;
    }

    int posInOutput = 0;
    int nBitsDecoded = 0;
    uint16_t current = 0;
    while (*msg) {
        char* pos = strchr(valid_base32_chars, toupper(*msg));
        if (pos == NULL) {
            return -1;
        }
        int value = (pos - valid_base32_chars);
        current = current << 5 | value;
        nBitsDecoded += 5;
        if (nBitsDecoded >= 8) {
            int bitsToKeep = nBitsDecoded - 8;
            (*output)[posInOutput++] = current >> bitsToKeep;
            int tmp = 16 - bitsToKeep;
            current = (current << tmp) >> tmp;
            nBitsDecoded -= 8;
        }
        msg++;
    }
    return posInOutput;
}
