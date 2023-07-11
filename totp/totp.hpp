#pragma once
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>

#ifdef __cplusplus
#include <string>
#include <tuple>
#include <vector>
#include <exception>
#endif

namespace totp {

namespace sh1 {
/* sha1.h */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/** \def SHA1_HASH_BITS
 * definees the size of a SHA-1 hash in bits 
 */

/** \def SHA1_HASH_BYTES
 * definees the size of a SHA-1 hash in bytes 
 */

/** \def SHA1_BLOCK_BITS
 * definees the size of a SHA-1 input block in bits 
 */

/** \def SHA1_BLOCK_BYTES
 * definees the size of a SHA-1 input block in bytes 
 */
#define SHA1_HASH_BITS  160
#define SHA1_HASH_BYTES (SHA1_HASH_BITS/8)
#define SHA1_BLOCK_BITS 512
#define SHA1_BLOCK_BYTES (SHA1_BLOCK_BITS/8)
#define LITTLE_ENDIAN

/** \typedef sha1_ctx_t
 * \brief SHA-1 context type
 * 
 * A vatiable of this type may hold the state of a SHA-1 hashing process
 */
typedef struct {
	uint32_t h[5];
	uint64_t length;
} sha1_ctx_t;

/** \typedef sha1_hash_t
 * \brief hash value type
 * A variable of this type may hold a SHA-1 hash value 
 */
/*
typedef uint8_t sha1_hash_t[SHA1_HASH_BITS/8];
*/

/** \fn sha1_init(sha1_ctx_t *state)
 * \brief initializes a SHA-1 context
 * This function sets a ::sha1_ctx_t variable to the initialization vector
 * for SHA-1 hashing.
 * \param state pointer to the SHA-1 context variable
 */
static void sha1_init(sha1_ctx_t* state) {
	state->h[0] = 0x67452301;
	state->h[1] = 0xefcdab89;
	state->h[2] = 0x98badcfe;
	state->h[3] = 0x10325476;
	state->h[4] = 0xc3d2e1f0;
	state->length = 0;
}

/********************************************************************************************************/
/* some helping functions */
static uint32_t rotl32(uint32_t n, uint8_t bits) {
	return ((n << bits) | (n >> (32 - bits)));
}

static uint32_t change_endian32(uint32_t x) {
	return (((x) << 24) | ((x) >> 24) | (((x) & 0x0000ff00) << 8) | (((x) & 0x00ff0000) >> 8));
}

/* three SHA-1 inner functions */
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) ^ ((~x) & z));
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) ^ (x & z) ^ (y & z));
}

static uint32_t parity(uint32_t x, uint32_t y, uint32_t z) {
	return ((x ^ y) ^ z);
}

#define MASK 0x0000000f

typedef uint32_t(*pf_t)(uint32_t x, uint32_t y, uint32_t z);

/** \fn sha1_nextBlock(sha1_ctx_t *state, const void *block)
 *  \brief process one input block
 * This function processes one input block and updates the hash context 
 * accordingly
 * \param state pointer to the state variable to update
 * \param block pointer to the message block to process
 */
static void sha1_nextBlock(sha1_ctx_t* state, const void* block) {
	uint32_t a[5];
	uint32_t w[16];
	uint32_t temp;
	uint8_t t, s, fi, fib;
	pf_t f[] = { ch,parity,maj,parity };
	uint32_t k[4] = { 0x5a827999,
					0x6ed9eba1,
					0x8f1bbcdc,
					0xca62c1d6 };

	/* load the w array (changing the endian and so) */
	for (t = 0; t < 16; ++t) {
		w[t] = change_endian32(((uint32_t*)block)[t]);
	}

	/* load the state */
	memcpy(a, state->h, 5 * sizeof(uint32_t));


	/* the fun stuff */
	for (fi = 0, fib = 0, t = 0; t <= 79; ++t) {
		s = t & MASK;
		if (t >= 16) {
			w[s] = rotl32(w[(s + 13) & MASK] ^ w[(s + 8) & MASK] ^
				w[(s + 2) & MASK] ^ w[s], 1);
		}

		uint32_t dtemp;
		temp = rotl32(a[0], 5) + (dtemp = f[fi](a[1], a[2], a[3])) + a[4] + k[fi] + w[s];
		memmove(&(a[1]), &(a[0]), 4 * sizeof(uint32_t)); /* e=d; d=c; c=b; b=a; */
		a[0] = temp;
		a[2] = rotl32(a[2], 30); /* we might also do rotr32(c,2) */
		fib++;
		if (fib == 20) {
			fib = 0;
			fi = (fi + 1) % 4;
		}
	}

	/* update the state */
	for (t = 0; t < 5; ++t) {
		state->h[t] += a[t];
	}
	state->length += 512;
}

/** \fn sha1_lastBlock(sha1_ctx_t *state, const void *block, uint16_t length_b)
 * \brief processes the given block and finalizes the context
 * This function processes the last block in a SHA-1 hashing process.
 * The block should have a maximum length of a single input block.
 * \param state pointer to the state variable to update and finalize
 * \param block pointer to the message block to process
 * \param length length of the message block in bits  
 */
static void sha1_lastBlock(sha1_ctx_t* state, const void* block, uint16_t length) {
	uint8_t lb[SHA1_BLOCK_BYTES]; /* local block */
	while (length >= SHA1_BLOCK_BITS) {
		sha1_nextBlock(state, block);
		length -= SHA1_BLOCK_BITS;
		block = (uint8_t*)block + SHA1_BLOCK_BYTES;
	}
	state->length += length;
	memset(lb, 0, SHA1_BLOCK_BYTES);
	memcpy(lb, block, (length + 7) >> 3);

	/* set the final one bit */
	lb[length >> 3] |= 0x80 >> (length & 0x07);

	if (length > 512 - 64 - 1) { /* not enouth space for 64bit length value */
		sha1_nextBlock(state, lb);
		state->length -= 512;
		memset(lb, 0, SHA1_BLOCK_BYTES);
	}
	/* store the 64bit length value */
    #if defined LITTLE_ENDIAN
	/* this is now rolled up */
	uint8_t i;
	for (i = 0; i < 8; ++i) {
		lb[56 + i] = ((uint8_t*)&(state->length))[7 - i];
	}
    #elif defined BIG_ENDIAN
	* ((uint64_t) & (lb[56])) = state->length;
    #endif
	sha1_nextBlock(state, lb);
}

/** \fn sha1_ctx2hash(sha1_hash_t *dest, sha1_ctx_t *state)
 * \brief convert a state variable into an actual hash value
 * Writes the hash value corresponding to the state to the memory pointed by dest.
 * \param dest pointer to the hash value destination
 * \param state pointer to the hash context
 */
static void sha1_ctx2hash(void* dest, sha1_ctx_t* state) {
	#if defined LITTLE_ENDIAN
	uint8_t i;
	for(i=0; i<5; ++i){
		((uint32_t*)dest)[i] = change_endian32(state->h[i]);
	}
    #elif BIG_ENDIAN
	if (dest != state->h)
		memcpy(dest, state->h, SHA1_HASH_BITS/8);
    #else
    # error unsupported endian type!
    #endif
}

/** \fn sha1(sha1_hash_t *dest, const void *msg, uint32_t length_b)
 * \brief hashing a message which in located entirely in RAM
 * This function automatically hashes a message which is entirely in RAM with
 * the SHA-1 hashing algorithm.
 * \param dest pointer to the hash value destination
 * \param msg  pointer to the message which should be hashed
 * \param length length of the message in bits
 */
static void sha1(void* dest, const void* msg, uint32_t length) {
	sha1_ctx_t s;
	sha1_init(&s);
	while (length & (~0x0001ff)) { /* length>=512 */
		sha1_nextBlock(&s, msg);
		msg = (uint8_t*)msg + SHA1_BLOCK_BITS / 8; /* increment pointer to next block */
		length -= SHA1_BLOCK_BITS;
	}
	sha1_lastBlock(&s, msg, length);
	sha1_ctx2hash(dest, &s);
}

}

namespace hmac {
/* hmac-sha1.h */
/*
	This file is part of the AVR-Crypto-Lib.
	Copyright (C) 2008  Daniel Otte (daniel.otte@rub.de)

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define HMAC_SHA1_BITS        SHA1_HASH_BITS
#define HMAC_SHA1_BYTES       SHA1_HASH_BYTES
#define HMAC_SHA1_BLOCK_BITS  SHA1_BLOCK_BITS
#define HMAC_SHA1_BLOCK_BYTES SHA1_BLOCK_BYTES
#define IPAD 0x36
#define OPAD 0x5C

typedef struct {
    sh1::sha1_ctx_t a, b;
} hmac_sha1_ctx_t;

static void hmac_sha1_init(hmac_sha1_ctx_t* s, const void* key, uint16_t keylength_b) {
	uint8_t buffer[SHA1_BLOCK_BYTES];
	uint8_t i;

	memset(buffer, 0, SHA1_BLOCK_BYTES);
	if (keylength_b > SHA1_BLOCK_BITS) {
        sh1::sha1((void*)buffer, key, keylength_b);
	}
	else {
		memcpy(buffer, key, (keylength_b + 7) / 8);
	}

	for (i = 0; i < SHA1_BLOCK_BYTES; ++i) {
		buffer[i] ^= IPAD;
	}
	sha1_init(&(s->a));
	sha1_nextBlock(&(s->a), buffer);

	for (i = 0; i < SHA1_BLOCK_BYTES; ++i) {
		buffer[i] ^= IPAD ^ OPAD;
	}
	sha1_init(&(s->b));
	sha1_nextBlock(&(s->b), buffer);


    #if defined SECURE_WIPE_BUFFER
	memset(buffer, 0, SHA1_BLOCK_BYTES);
    #endif
}

static void hmac_sha1_nextBlock(hmac_sha1_ctx_t* s, const void* block) {
	sha1_nextBlock(&(s->a), block);
}

static void hmac_sha1_lastBlock(hmac_sha1_ctx_t* s, const void* block, uint16_t length_b) {
	while (length_b >= SHA1_BLOCK_BITS) {
		sha1_nextBlock(&s->a, block);
		block = (uint8_t*)block + SHA1_BLOCK_BYTES;
		length_b -= SHA1_BLOCK_BITS;
	}
	sha1_lastBlock(&s->a, block, length_b);
}

static void hmac_sha1_final(void* dest, hmac_sha1_ctx_t* s) {
	sha1_ctx2hash(dest, &s->a);
	sha1_lastBlock(&s->b, dest, SHA1_HASH_BITS);
	sha1_ctx2hash(dest, &(s->b));
}

/*
 * keylength_b in bits!
 * message length in bits!
 */
static void hmac_sha1(void* dest, const void* key, uint16_t keylength_b, const void* msg, uint32_t msglength_b) {
    sh1::sha1_ctx_t s;
	uint8_t i;
	uint8_t buffer[SHA1_BLOCK_BYTES];

	memset(buffer, 0, SHA1_BLOCK_BYTES);

	/* if key is larger than a block we have to hash it*/
	if (keylength_b > SHA1_BLOCK_BITS) {
        sh1::sha1((void*)buffer, key, keylength_b);
	}
	else {
		memcpy(buffer, key, (keylength_b + 7) / 8);
	}

	for (i = 0; i < SHA1_BLOCK_BYTES; ++i) {
		buffer[i] ^= IPAD;
	}
	sha1_init(&s);
	sha1_nextBlock(&s, buffer);
	while (msglength_b >= SHA1_BLOCK_BITS) {
		sha1_nextBlock(&s, msg);
		msg = (uint8_t*)msg + SHA1_BLOCK_BYTES;
		msglength_b -= SHA1_BLOCK_BITS;
	}
	sha1_lastBlock(&s, msg, msglength_b);
	/* since buffer still contains key xor ipad we can do ... */
	for (i = 0; i < SHA1_BLOCK_BYTES; ++i) {
		buffer[i] ^= IPAD ^ OPAD;
	}
	sha1_ctx2hash(dest, &s); /* save inner hash temporary to dest */
	sha1_init(&s);
	sha1_nextBlock(&s, buffer);
	sha1_lastBlock(&s, dest, SHA1_HASH_BITS);
	sha1_ctx2hash(dest, &s);
}

}

namespace base32 {
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

static const char* valid_base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int decode_base32(const char* msg, uint8_t** output) {
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
		 const char* pos = strchr(valid_base32_chars, toupper(*msg));
		 if (pos == NULL) {
			 return -1;
		 }
		 int value = int(pos - valid_base32_chars);
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

}

namespace totp {

/**
 * Returns the number of periods of 30 seconds since the beginning of the
 * Unix Epoch as a 8 byte value.
 */
static void get_half_minutes_elapsed(uint8_t* output) {
    time_t now = time(NULL);
    time_t half_minutes = now / 30;
    int n = sizeof(time_t);
    memset(output, 0, 8);
    for (int i = 0 ; i < n ; i++) {
        output[7 - i] = half_minutes & 0xFF;
        half_minutes = half_minutes >> 8;
    }
}

static int get_totp(const uint8_t* secret, size_t secret_size, char* code) {
	unsigned char half_minutes[8];
	get_half_minutes_elapsed(half_minutes);

	uint8_t hash[20];

	// The hmac_sha1 expects sizes in bits, not bytes, hence the x8
    hmac::hmac_sha1(hash, secret, uint16_t(secret_size * 8), half_minutes, 8 * 8);

	int offset = hash[19] & 0xf;
	uint32_t binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
		| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

	int otp = binary % 1000000;
	for (int i = 0; i < 6; i++) {
		code[5 - i] = '0' + (otp % 10);
		otp = otp / 10;
	}
	code[6] = '\0';

	return 30 - (time(NULL) % 30);
}

}

#ifdef __cplusplus

static std::tuple<int, std::string> get_totp(const char* base32_key, int interval = 30) {
	uint8_t* key{ nullptr };
	int size_key = base32::decode_base32(base32_key, &key);
	if (size_key == -1) {
		char buffer[256];
		sprintf_s(buffer, 256, "The given secret '%s' is not a valid base32 encoded value\n", base32_key);
		throw std::exception(buffer);
	}
	if (size_key == -2) {
		char buffer[256];
		sprintf_s(buffer, 256, "Memory allocation error\n");
		throw std::exception(buffer);
	}

	std::vector<uint8_t> v_key;
	v_key.assign(key, key + size_key);
	if (key) {
		free(key);
	}

	char code[7];
	int lifetime = totp::get_totp(v_key.data(), 20, code);
	auto otp = std::string(code, strlen(code));
	return std::make_tuple(lifetime, otp);
}

#endif

}
