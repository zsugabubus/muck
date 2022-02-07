#ifndef MUCK_ASSERT_H
#define MUCK_ASSERT_H

#include <assert.h>

#ifndef NDEBUG
# define xassert(c) assert(c)
#else
# define xassert(c) ((void)(c))
#endif

#endif
