#ifndef MUCK_PTHREAD_H
#define MUCK_PTHREAD_H

#include <pthread.h>

#include "config.h"

#if !HAVE_PTHREAD_SETNAME_NP
# define pthread_setname_np(...) (void)0
#endif

#endif
