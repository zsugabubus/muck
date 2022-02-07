#ifndef MUCK_ATOMIC_H
#define MUCK_ATOMIC_H

#include <stdatomic.h>

#define ALIGNED_ATOMIC _Alignas(64)

#define atomic_exchange_lax(...) atomic_exchange_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_add_lax(...) atomic_fetch_add_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_and_lax(...) atomic_fetch_and_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_or_lax(...) atomic_fetch_or_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_sub_lax(...) atomic_fetch_sub_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_xor_lax(...) atomic_fetch_xor_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_load_lax(...) atomic_load_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_store_lax(...) atomic_store_explicit(__VA_ARGS__, memory_order_relaxed)

#endif
