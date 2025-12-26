#pragma once

#include <Arduino.h>

#define SHA1_BLOCK_LEN 64
#define SHA1_HASH_LEN 20

// Cache-aligned hash state for optimal ARM Cortex-M4 performance
// Frequently accessed fields placed at start for better cache behavior
#if defined(ARDUINO_ARCH_RENESAS) || defined(__ARM_ARCH)
#define DUCO_CACHE_ALIGN __attribute__((aligned(32)))
#else
#define DUCO_CACHE_ALIGN
#endif

struct DUCO_CACHE_ALIGN duco_hash_state_t {
	// Hot path: These are accessed every hash iteration
	uint32_t tempState[5];     // SHA-1 intermediate state (accessed every block)
	union {
		uint8_t result[SHA1_HASH_LEN];
		uint32_t result32[5];  // For fast 32-bit comparison
	};
	uint8_t buffer[SHA1_BLOCK_LEN];  // Message buffer with nonce
	uint8_t prev_nonce_len;

	// Cold path: These are only accessed once per job
	uint32_t base_words[10];   // Cached first 10 words of prevHash

	uint8_t block_offset;
	uint8_t total_bytes;
};

void duco_hash_init(duco_hash_state_t * hasher, char const * prevHash);

uint8_t const * duco_hash_try_nonce(duco_hash_state_t * hasher, char const * nonce, uint8_t nonce_len);

// Fast 32-bit result access for ARM comparison optimization
uint32_t const * duco_hash_try_nonce32(duco_hash_state_t * hasher, char const * nonce, uint8_t nonce_len);
