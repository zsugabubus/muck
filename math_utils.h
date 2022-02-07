#ifndef MUCK_MATH_H
#define MUCK_MATH_H

#define MINMAX_Generic(a, MIN) _Generic(a, \
	int: MIN##_int, \
	long int: MIN##_longint \
)
#define MINMAX_impl(type, MIN, name, cmp) \
	static inline type MIN##_##name(type a, type b) { \
		return a cmp b ? a : b; \
	}
#define MIN(a, b) MINMAX_Generic(a, MIN)(a, b)
#define MAX(a, b) MINMAX_Generic(a, MAX)(a, b)
#define MAXMIN(a, b, c) MAX(a, MIN(b, c))
#define DIFFSIGN(a, b) (((a) > (b)) - ((a) < (b)))

/* Huh? */
#define SWAP(type, a, b) do { \
	type SWAP = (a); \
	(a) = (b); \
	(b) = SWAP; \
} while (0);

#define NUMERIC_TYPES \
	/* xmacro(type, name) */ \
	xmacro(int, int) \
	xmacro(long int, longint)

#define xmacro(type, name) \
	MINMAX_impl(type, MIN, name, <=) \
	MINMAX_impl(type, MAX, name, >=) \

	NUMERIC_TYPES

#undef xmacro

#endif
