#ifndef BIRDLOCK_H
#define BIRDLOCK_H

#include <stdatomic.h>
#include <emmintrin.h>

#define BIRDLOCK_INITIALIZER { 0 }

/**
 * SPMC binary read-write lock.
 */
typedef struct {
	unsigned char _Atomic state; /* {rd slot} * 2 + {new data slot} */
} BirdLock;

/**
 * @return 1 if new data is available, 0 otherwise
 */
static inline unsigned char
birdlock_rd_test(BirdLock *lock)
{
	/* rn    n
	 * 00 -> 0
	 * 01 -> 1
	 * 10 -> 1
	 * 11 -> 0 */
	return !((atomic_load_explicit(&lock->state, memory_order_relaxed) - 1) & 2);
}

/**
 * @return 0 or 1, index of readable object
 */
static inline unsigned char
birdlock_rd_acquire(BirdLock *lock)
{
	/* rn -> nn
	 * 00 -> 00 (-> 00)
	 * 01 -> 11 (-> 11)
	 * 10 -> 00 (-> 00)
	 * 11 -> 11 (-> 11) */
	unsigned char state = atomic_load_explicit(&lock->state, memory_order_acquire);
	atomic_store_explicit(&lock->state, -(state & 1), memory_order_relaxed);
	return state & 1;
}

/**
 * @return 0 or 1, index of writable object
 */
static inline unsigned char
birdlock_wr_acquire(BirdLock *lock)
{
	return !birdlock_rd_acquire(lock);
}

/**
 * Commit write.
 */
static inline void
birdlock_wr_release(BirdLock const *lock)
{
	/* rn    rn
	 * 00 -> 01
	 * 10 -> (unreachable)
	 * 01 -> (unreachable)
	 * 11 -> 10 */
	atomic_store_explicit(&lock->state,
			atomic_load_explicit(&lock->state, memory_order_relaxed) ^ 1,
			memory_order_release);
}

#endif
