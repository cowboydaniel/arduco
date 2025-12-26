#include "duco_hash.h"

#if defined(ARDUINO_ARCH_RENESAS)
// Use aggressive tuning on Renesas RA (e.g., UNO R4 WiFi/Minima) to squeeze more hashrate
#pragma GCC optimize ("Ofast","unroll-loops","tree-vectorize","rename-registers","inline-functions")
#define DUCO_HOT_ATTR __attribute__((hot, flatten, optimize("O3")))
#else
#pragma GCC optimize ("-Ofast")
#define DUCO_HOT_ATTR
#endif

#define sha1_rotl(bits,word)     (((word) << (bits)) | ((word) >> (32 - (bits))))

// Fully unrolled SHA-1 round macros for maximum performance
// Round type 1: rounds 0-19 - f = (b & c) | ((~b) & d)
#define SHA1_R1(a,b,c,d,e,w) \
	e += sha1_rotl(5,a) + ((b & c) | ((~b) & d)) + 0x5a827999 + w; \
	b = sha1_rotl(30,b);

// Round type 2: rounds 20-39 - f = b ^ c ^ d
#define SHA1_R2(a,b,c,d,e,w) \
	e += sha1_rotl(5,a) + (b ^ c ^ d) + 0x6ed9eba1 + w; \
	b = sha1_rotl(30,b);

// Round type 3: rounds 40-59 - f = (b & c) | (b & d) | (c & d)
#define SHA1_R3(a,b,c,d,e,w) \
	e += sha1_rotl(5,a) + ((b & c) | (b & d) | (c & d)) + 0x8f1bbcdc + w; \
	b = sha1_rotl(30,b);

// Round type 4: rounds 60-79 - f = b ^ c ^ d
#define SHA1_R4(a,b,c,d,e,w) \
	e += sha1_rotl(5,a) + (b ^ c ^ d) + 0xca62c1d6 + w; \
	b = sha1_rotl(30,b);

// Word expansion macro
#define SHA1_EXPAND(w,i) (w[i&15] = sha1_rotl(1, w[(i-3)&15] ^ w[(i-8)&15] ^ w[(i-14)&15] ^ w[i&15]))

DUCO_HOT_ATTR void duco_hash_block(duco_hash_state_t * hasher) {
	// NOTE: keeping this static improves performance quite a lot
	static uint32_t w[16];

	// Load base words (first 10 words are constant per job)
	w[0] = hasher->base_words[0];
	w[1] = hasher->base_words[1];
	w[2] = hasher->base_words[2];
	w[3] = hasher->base_words[3];
	w[4] = hasher->base_words[4];
	w[5] = hasher->base_words[5];
	w[6] = hasher->base_words[6];
	w[7] = hasher->base_words[7];
	w[8] = hasher->base_words[8];
	w[9] = hasher->base_words[9];

	// Load remaining 6 words from buffer (contains nonce)
	uint8_t const * buf = hasher->buffer;
	w[10] = (uint32_t(buf[40]) << 24) | (uint32_t(buf[41]) << 16) | (uint32_t(buf[42]) << 8) | uint32_t(buf[43]);
	w[11] = (uint32_t(buf[44]) << 24) | (uint32_t(buf[45]) << 16) | (uint32_t(buf[46]) << 8) | uint32_t(buf[47]);
	w[12] = (uint32_t(buf[48]) << 24) | (uint32_t(buf[49]) << 16) | (uint32_t(buf[50]) << 8) | uint32_t(buf[51]);
	w[13] = (uint32_t(buf[52]) << 24) | (uint32_t(buf[53]) << 16) | (uint32_t(buf[54]) << 8) | uint32_t(buf[55]);
	w[14] = (uint32_t(buf[56]) << 24) | (uint32_t(buf[57]) << 16) | (uint32_t(buf[58]) << 8) | uint32_t(buf[59]);
	w[15] = (uint32_t(buf[60]) << 24) | (uint32_t(buf[61]) << 16) | (uint32_t(buf[62]) << 8) | uint32_t(buf[63]);

	uint32_t a = hasher->tempState[0];
	uint32_t b = hasher->tempState[1];
	uint32_t c = hasher->tempState[2];
	uint32_t d = hasher->tempState[3];
	uint32_t e = hasher->tempState[4];

	// Rounds 10-19 (type 1) - first 6 use direct words, rest need expansion
	SHA1_R1(a,b,c,d,e, w[10]); SHA1_R1(e,a,b,c,d, w[11]);
	SHA1_R1(d,e,a,b,c, w[12]); SHA1_R1(c,d,e,a,b, w[13]);
	SHA1_R1(b,c,d,e,a, w[14]); SHA1_R1(a,b,c,d,e, w[15]);
	SHA1_R1(e,a,b,c,d, SHA1_EXPAND(w,16)); SHA1_R1(d,e,a,b,c, SHA1_EXPAND(w,17));
	SHA1_R1(c,d,e,a,b, SHA1_EXPAND(w,18)); SHA1_R1(b,c,d,e,a, SHA1_EXPAND(w,19));

	// Rounds 20-39 (type 2)
	SHA1_R2(a,b,c,d,e, SHA1_EXPAND(w,20)); SHA1_R2(e,a,b,c,d, SHA1_EXPAND(w,21));
	SHA1_R2(d,e,a,b,c, SHA1_EXPAND(w,22)); SHA1_R2(c,d,e,a,b, SHA1_EXPAND(w,23));
	SHA1_R2(b,c,d,e,a, SHA1_EXPAND(w,24)); SHA1_R2(a,b,c,d,e, SHA1_EXPAND(w,25));
	SHA1_R2(e,a,b,c,d, SHA1_EXPAND(w,26)); SHA1_R2(d,e,a,b,c, SHA1_EXPAND(w,27));
	SHA1_R2(c,d,e,a,b, SHA1_EXPAND(w,28)); SHA1_R2(b,c,d,e,a, SHA1_EXPAND(w,29));
	SHA1_R2(a,b,c,d,e, SHA1_EXPAND(w,30)); SHA1_R2(e,a,b,c,d, SHA1_EXPAND(w,31));
	SHA1_R2(d,e,a,b,c, SHA1_EXPAND(w,32)); SHA1_R2(c,d,e,a,b, SHA1_EXPAND(w,33));
	SHA1_R2(b,c,d,e,a, SHA1_EXPAND(w,34)); SHA1_R2(a,b,c,d,e, SHA1_EXPAND(w,35));
	SHA1_R2(e,a,b,c,d, SHA1_EXPAND(w,36)); SHA1_R2(d,e,a,b,c, SHA1_EXPAND(w,37));
	SHA1_R2(c,d,e,a,b, SHA1_EXPAND(w,38)); SHA1_R2(b,c,d,e,a, SHA1_EXPAND(w,39));

	// Rounds 40-59 (type 3)
	SHA1_R3(a,b,c,d,e, SHA1_EXPAND(w,40)); SHA1_R3(e,a,b,c,d, SHA1_EXPAND(w,41));
	SHA1_R3(d,e,a,b,c, SHA1_EXPAND(w,42)); SHA1_R3(c,d,e,a,b, SHA1_EXPAND(w,43));
	SHA1_R3(b,c,d,e,a, SHA1_EXPAND(w,44)); SHA1_R3(a,b,c,d,e, SHA1_EXPAND(w,45));
	SHA1_R3(e,a,b,c,d, SHA1_EXPAND(w,46)); SHA1_R3(d,e,a,b,c, SHA1_EXPAND(w,47));
	SHA1_R3(c,d,e,a,b, SHA1_EXPAND(w,48)); SHA1_R3(b,c,d,e,a, SHA1_EXPAND(w,49));
	SHA1_R3(a,b,c,d,e, SHA1_EXPAND(w,50)); SHA1_R3(e,a,b,c,d, SHA1_EXPAND(w,51));
	SHA1_R3(d,e,a,b,c, SHA1_EXPAND(w,52)); SHA1_R3(c,d,e,a,b, SHA1_EXPAND(w,53));
	SHA1_R3(b,c,d,e,a, SHA1_EXPAND(w,54)); SHA1_R3(a,b,c,d,e, SHA1_EXPAND(w,55));
	SHA1_R3(e,a,b,c,d, SHA1_EXPAND(w,56)); SHA1_R3(d,e,a,b,c, SHA1_EXPAND(w,57));
	SHA1_R3(c,d,e,a,b, SHA1_EXPAND(w,58)); SHA1_R3(b,c,d,e,a, SHA1_EXPAND(w,59));

	// Rounds 60-79 (type 4)
	SHA1_R4(a,b,c,d,e, SHA1_EXPAND(w,60)); SHA1_R4(e,a,b,c,d, SHA1_EXPAND(w,61));
	SHA1_R4(d,e,a,b,c, SHA1_EXPAND(w,62)); SHA1_R4(c,d,e,a,b, SHA1_EXPAND(w,63));
	SHA1_R4(b,c,d,e,a, SHA1_EXPAND(w,64)); SHA1_R4(a,b,c,d,e, SHA1_EXPAND(w,65));
	SHA1_R4(e,a,b,c,d, SHA1_EXPAND(w,66)); SHA1_R4(d,e,a,b,c, SHA1_EXPAND(w,67));
	SHA1_R4(c,d,e,a,b, SHA1_EXPAND(w,68)); SHA1_R4(b,c,d,e,a, SHA1_EXPAND(w,69));
	SHA1_R4(a,b,c,d,e, SHA1_EXPAND(w,70)); SHA1_R4(e,a,b,c,d, SHA1_EXPAND(w,71));
	SHA1_R4(d,e,a,b,c, SHA1_EXPAND(w,72)); SHA1_R4(c,d,e,a,b, SHA1_EXPAND(w,73));
	SHA1_R4(b,c,d,e,a, SHA1_EXPAND(w,74)); SHA1_R4(a,b,c,d,e, SHA1_EXPAND(w,75));
	SHA1_R4(e,a,b,c,d, SHA1_EXPAND(w,76)); SHA1_R4(d,e,a,b,c, SHA1_EXPAND(w,77));
	SHA1_R4(c,d,e,a,b, SHA1_EXPAND(w,78)); SHA1_R4(b,c,d,e,a, SHA1_EXPAND(w,79));

	a += 0x67452301;
	b += 0xefcdab89;
	c += 0x98badcfe;
	d += 0x10325476;
	e += 0xc3d2e1f0;

	// Store as 32-bit words directly for fast comparison on ARM
	// Use big-endian byte swap for SHA-1 compatibility
#if defined(ARDUINO_ARCH_RENESAS) || defined(__ARM_ARCH)
	// ARM has __REV intrinsic for fast byte swap, but we inline it for portability
	hasher->result32[0] = __builtin_bswap32(a);
	hasher->result32[1] = __builtin_bswap32(b);
	hasher->result32[2] = __builtin_bswap32(c);
	hasher->result32[3] = __builtin_bswap32(d);
	hasher->result32[4] = __builtin_bswap32(e);
#else
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
#endif
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

DUCO_HOT_ATTR uint32_t const * duco_hash_try_nonce32(duco_hash_state_t * hasher, char const * nonce, uint8_t nonce_len) {
	duco_hash_set_nonce(hasher, nonce, nonce_len);
	duco_hash_block(hasher);

	return hasher->result32;
}
