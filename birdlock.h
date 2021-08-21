#ifndef BIRDLOCK_H
#define BIRDLOCK_H

#include <stdatomic.h>
#include <emmintrin.h>

#define BIRDLOCK_INITIALIZER { 0, 0 }

/**
 * SPMC binary read-write lock.
 */
typedef struct {
	unsigned char _Atomic rd, new_rd;
} BirdLock;

/**
 * @return 0 or 1, index of readable object
 */
static inline unsigned char
birdlock_rd_acquire(BirdLock *lock)
{
	/* atomic_compare_exchange_strong_explicit(&new_rd, &rd, 2, memory_order_relaxed, memory_order_acquire); */

	for (unsigned char v; lock->rd != (v = atomic_load_explicit(&lock->new_rd, memory_order_acquire));)
		atomic_store_explicit(&lock->rd, v, memory_order_relaxed);
	return lock->rd;
}

/**
 * @return 0 or 1, index of writable object
 */
static inline unsigned char
birdlock_wr_acquire(BirdLock *lock)
{
	for (unsigned char v; lock->new_rd != (v = atomic_load_explicit(&lock->rd, memory_order_relaxed));) {
		atomic_store_explicit(&lock->new_rd, v, memory_order_relaxed);
		_mm_pause(); /* Give a little more chance for readers. */
	}
	return !lock->new_rd;
}

/**
 * Finish writing.
 */
static inline void
birdlock_wr_release(BirdLock const *lock)
{
	atomic_store_explicit(&lock->new_rd, !lock->new_rd, memory_order_release);
}

#endif /* BIRDLOCK_H */
