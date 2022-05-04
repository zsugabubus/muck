#ifndef MUCK_FILES_H
#define MUCK_FILES_H

#include <stdint.h>
#include <stdio.h>

typedef struct Error Error;
typedef struct ExprParserContext ExprParserContext;
typedef struct File File;
typedef struct FileReadError FileReadError;

enum FilterIndex {
	FILTER_ALL,
	FILTER_FILES,
	FILTER_PLAYLISTS,
	FILTER_CUSTOM_0,
	FILTER_COUNT = FILTER_CUSTOM_0 + 2,
};

extern int32_t nfiles[FILTER_COUNT];
extern File **files;
/* TODO: Queue is live queue has p=^queue$ filter. In non-live mode we can select tracks etc. */
extern int live;
/**
 * .[live] is the currently used filter.
 */
extern uint8_t cur_filter[2];

void files_init(Error *error);
void files_destroy(void);

File *files_seek_wrap(int32_t pos, int whence, int wrap);
File *files_seek(int32_t pos, int whence);
File *files_seek_rnd(int whence);

void files_select(File const *f);
void files_plumb(FILE *stream);

void files_set_live(int new_live);
void files_set_order(char *spec);
void files_set_order_dup(char const *spec);
void files_reset_order(void);
void files_set_filter(ExprParserContext *parser, char const *s);

int files_move(File const *f, int32_t pos, int whence);

char const *files_get_order(void);

/**
 * Mark file dirty and re-evaluate filters immediately and check whether it is
 * still in order.
 *
 * Use it only if a few files is about to change because it scales poorly.
 */
void files_dirty_single(File *f);
/**
 * Forcefully mark collection unordered and unsorted.
 *
 * Use it if several files are about to change because it is more efficient.
 */
void files_dirty_batch(void);

#endif
