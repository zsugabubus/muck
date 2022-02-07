#ifndef MUCK_STDIO_H
#define MUCK_STDIO_H

#include <stdio.h>

#define safe_sprintf(buf, format, ...) \
	((int)sizeof buf <= snprintf(buf, sizeof buf, format, __VA_ARGS__) ? -1 : 0)

#endif
