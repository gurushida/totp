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


/**
 * Given a secret key, calculates the 6 digit time-based one-time
 * password obtained with HMAC-SHA1 as described in RFC 6238.
 *
 * @param secret The secret key used to seed the MFA generator
 * @param secret_size The size of the secret array in bytes
 * @param code The output array where the 6 digit code will be stored as a string.
 *             Must be at least 7 bytes long.
 * @return The lifetime in seconds of the calculated MFA code, i.e. the number of
 *         seconds the code can be used before becoming obsolete.
 */
int get_totp(u_int8_t* secret, size_t secret_size, char* code);
