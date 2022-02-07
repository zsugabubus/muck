#ifndef MUCK_FILE_H
#define MUCK_FILE_H

#include <limits.h>
#include <stdint.h>

#include "metadata.h"

enum {
	FILE_METADATAX_BUFSZ = 20,
};

typedef struct Playlist Playlist;

typedef struct File {
	char *url; /* URL "\0" [METADATA-VALUE [";" METADATA-VALUE]... "\0"]... */
	enum FileType {
		/* Files have metadata. */
		F_URL, /**< Not prefixed by */
		F_FILE, /**< Handled by FFmpeg. */

		/* Containers. */
		F_PLAYLIST, /**< Handled by us. */
		F_PLAYLIST_COMPRESSED,
		F_PLAYLIST_DIRECTORY,
	} type: CHAR_BIT;
	uint8_t filter_mask; /* (1 << FilterIndex) | ... */
	int16_t playlist_index; /* Parent: playlists[playlist_index]. */
	int32_t playlist_order; /* Order inside playlists. */
	int32_t index[2]; /* files[x->index[live]] == x */
	uint16_t metadata[M_NB]; /* x => url + metadata[x]; 0 if key not present. */
} File;

void file_free(File *f);

char const *file_get_metadata(File const *f, enum MetadataX m, char buf[FILE_METADATAX_BUFSZ]);
Playlist *file_get_playlist(File const *f);
struct timespec file_get_mtim(File const *f);

#endif
