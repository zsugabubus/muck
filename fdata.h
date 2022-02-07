#ifndef MUCK_FDATA_H
#define MUCK_FDATA_H

#include <limits.h>
#include <time.h>

#include "file.h"

typedef struct PlayerMetadataEvent PlayerMetadataEvent;

typedef struct {
	File f;
	char buf[UINT16_MAX];
	size_t urlsz;
	size_t sz;
} FileData;

void fdata_reset(FileData *fdata, size_t urlsz);
void fdata_reset_with_url(FileData *fdata, char const *url);
int fdata_append(FileData *fdata, enum Metadata m, char const *value);
int fdata_writef(FileData *fdata, enum Metadata m, char const *format, ...);
int fdata_write_basic(FileData *fdata, PlayerMetadataEvent const *e);
int fdata_write_date(FileData *fdata, enum Metadata m, time_t time);
int fdata_save(FileData const *fdata, File *f);

#endif
