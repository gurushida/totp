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
 * Given a string representing a base32-encoded value, dynamically
 * allocates and fills an output array with the decoded bytes.
 *
 * @param msg The base32 value to decode
 * @param output The output array
 * @return The number of decoded bytes on success
 *         -1 if the given msg is not a valid base32 value
 *         -2 if the output array cannot be allocated
 */
int decode_base32(char* msg, u_int8_t* *output);
