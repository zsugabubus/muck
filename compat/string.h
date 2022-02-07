#ifndef MUCK_STRING_H
#define MUCK_STRING_H

#include <string.h>

#include "config.h"

#if !HAVE_STRCHRNUL
static inline char *
strchrnul(char const *s, char c)
{
	char *ret = strchr(s, c);
	return ret ? ret : s + strlen(s);
}
#endif

#endif
