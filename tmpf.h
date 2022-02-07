#ifndef MUCK_TMPF_H
#define MUCK_TMPF_H

#include <limits.h>

typedef struct Error Error;

typedef struct {
	char pathname[PATH_MAX];
} TemporaryFile;

FILE *tmpf_open(TemporaryFile *tmpf, Error *error);
void tmpf_close(TemporaryFile *tmpf);
FILE *tmpf_edit(TemporaryFile *tmpf);
char *tmpf_readline(TemporaryFile *tmpf);

#endif
