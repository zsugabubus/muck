#ifndef MUCK_RND_H
#define MUCK_RND_H

#include <stdint.h>

/**
 * xorshift* context.
 *
 * @see https://en.wikipedia.org/wiki/Xorshift
 */
typedef union {
	struct {
		uint64_t a, b;
	};
	uint8_t bytes[16];
} RndState;

int rnd_init(RndState *state);

/**
 * Generate a good random number in range [0..UINT64_MAX].
 */
uint64_t rnd_next(RndState *state);

/**
 * Generate a uniform random number in range [0..n).
 */
uint64_t rnd_nextn(RndState *state, uint64_t n);

#endif
