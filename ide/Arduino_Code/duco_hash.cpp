#include "duco_hash.h"

#if defined(ARDUINO_ARCH_RENESAS)
// Use aggressive tuning on Renesas RA (e.g., UNO R4 WiFi/Minima) to squeeze more hashrate
#pragma GCC optimize ("Ofast","unroll-loops","tree-vectorize","rename-registers","inline-functions")
#define DUCO_HOT_ATTR __attribute__((hot, flatten))
#else
#pragma GCC optimize ("-Ofast")
#define DUCO_HOT_ATTR
#endif

#define sha1_rotl(bits,word)     (((word) << (bits)) | ((word) >> (32 - (bits))))

DUCO_HOT_ATTR void duco_hash_block(duco_hash_state_t * hasher) {
	// NOTE: keeping this static improves performance quite a lot
	static uint32_t w[16];

	for (uint8_t i = 0; i < 10; i++) {
		w[i] = hasher->base_words[i];
	}

	for (uint8_t i = 10, i4 = 40; i < 16; i++, i4 += 4) {
		w[i] = (uint32_t(hasher->buffer[i4]) << 24) |
			(uint32_t(hasher->buffer[i4 + 1]) << 16) |
			(uint32_t(hasher->buffer[i4 + 2]) << 8) |
			(uint32_t(hasher->buffer[i4 + 3]));
	}
	
	uint32_t a = hasher->tempState[0];
	uint32_t b = hasher->tempState[1];
	uint32_t c = hasher->tempState[2];
	uint32_t d = hasher->tempState[3];
	uint32_t e = hasher->tempState[4];

	for (uint8_t i = 10; i < 80; i++) {
		if (i >= 16) {
			w[i & 15] = sha1_rotl(1, w[(i-3) & 15] ^ w[(i-8) & 15] ^ w[(i-14) & 15] ^ w[(i-16) & 15]);
		}

		uint32_t temp = sha1_rotl(5, a) + e + w[i & 15];
		if (i < 20) {
			temp += (b & c) | ((~b) & d);
			temp += 0x5a827999;
		} else if(i < 40) {
			temp += b ^ c ^ d;
			temp += 0x6ed9eba1;
		} else if(i < 60) {
			temp += (b & c) | (b & d) | (c & d);
			temp += 0x8f1bbcdc;
		} else {
			temp += b ^ c ^ d;
			temp += 0xca62c1d6;
		}

		e = d;
		d = c;
		c = sha1_rotl(30, b);
		b = a;
		a = temp;
	}

	a += 0x67452301;
	b += 0xefcdab89;
	c += 0x98badcfe;
	d += 0x10325476;
	e += 0xc3d2e1f0;

	hasher->result[0 * 4 + 0] = a >> 24;
	hasher->result[0 * 4 + 1] = a >> 16;
	hasher->result[0 * 4 + 2] = a >> 8;
	hasher->result[0 * 4 + 3] = a;
	hasher->result[1 * 4 + 0] = b >> 24;
	hasher->result[1 * 4 + 1] = b >> 16;
	hasher->result[1 * 4 + 2] = b >> 8;
	hasher->result[1 * 4 + 3] = b;
	hasher->result[2 * 4 + 0] = c >> 24;
	hasher->result[2 * 4 + 1] = c >> 16;
	hasher->result[2 * 4 + 2] = c >> 8;
	hasher->result[2 * 4 + 3] = c;
	hasher->result[3 * 4 + 0] = d >> 24;
	hasher->result[3 * 4 + 1] = d >> 16;
	hasher->result[3 * 4 + 2] = d >> 8;
	hasher->result[3 * 4 + 3] = d;
	hasher->result[4 * 4 + 0] = e >> 24;
	hasher->result[4 * 4 + 1] = e >> 16;
	hasher->result[4 * 4 + 2] = e >> 8;
	hasher->result[4 * 4 + 3] = e;
}

void duco_hash_init(duco_hash_state_t * hasher, char const * prevHash) {
	memcpy(hasher->buffer, prevHash, 40);

	if (prevHash == (void*)(0xffffffff)) {
		// NOTE: THIS IS NEVER CALLED
		// This is here to keep a live reference to hash_block
		// Otherwise GCC tries to inline it entirely into the main loop
		// Which causes massive perf degradation
		duco_hash_block(nullptr);
	}

	// Do first 10 rounds as these are going to be the same all time

	uint32_t a = 0x67452301;
	uint32_t b = 0xefcdab89;
	uint32_t c = 0x98badcfe;
	uint32_t d = 0x10325476;
	uint32_t e = 0xc3d2e1f0;

	static uint32_t w[10];

	for (uint8_t i = 0, i4 = 0; i < 10; i++, i4 += 4) {
		uint32_t const base_word = (uint32_t(hasher->buffer[i4]) << 24) |
			(uint32_t(hasher->buffer[i4 + 1]) << 16) |
			(uint32_t(hasher->buffer[i4 + 2]) << 8) |
			(uint32_t(hasher->buffer[i4 + 3]));
		w[i] = base_word;
		hasher->base_words[i] = base_word;
	}
	for (uint8_t i = 40; i < SHA1_BLOCK_LEN; i++) {
		hasher->buffer[i] = 0;
	}
	hasher->prev_nonce_len = 0;

	for (uint8_t i = 0; i < 10; i++) {
		uint32_t temp = sha1_rotl(5, a) + e + w[i & 15];
		temp += (b & c) | ((~b) & d);
		temp += 0x5a827999;

		e = d;
		d = c;
		c = sha1_rotl(30, b);
		b = a;
		a = temp;
	}

	hasher->tempState[0] = a;
	hasher->tempState[1] = b;
	hasher->tempState[2] = c;
	hasher->tempState[3] = d;
	hasher->tempState[4] = e;
}

DUCO_HOT_ATTR void duco_hash_set_nonce(duco_hash_state_t * hasher, char const * nonce, uint8_t nonce_len) {
	uint8_t * b = hasher->buffer;
	uint8_t const base_off = SHA1_HASH_LEN * 2;

	for (uint8_t i = 0; i < nonce_len; i++) {
		b[base_off + i] = nonce[i];
	}

	if (nonce_len != hasher->prev_nonce_len) {
		uint8_t const old_pad_pos = base_off + hasher->prev_nonce_len;
		for (uint8_t i = old_pad_pos; i < 62; i++) {
			b[i] = 0;
		}

		uint8_t const total_bytes = base_off + nonce_len;
		uint8_t const pad_pos = total_bytes;

		b[pad_pos] = 0x80;
		b[62] = total_bytes >> 5;
		b[63] = total_bytes << 3;

		hasher->prev_nonce_len = nonce_len;
	}
}

DUCO_HOT_ATTR uint8_t const * duco_hash_try_nonce(duco_hash_state_t * hasher, char const * nonce, uint8_t nonce_len) {
	duco_hash_set_nonce(hasher, nonce, nonce_len);
	duco_hash_block(hasher);

	return hasher->result;
}
