#include "assert_utils.h"
#include "compat/string.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>

#include "file.h"
#include "files.h"
#include "player.h"
#include "playlist.h"
#include "tui.h"

Playlist *
file_get_playlist(File const *f)
{
	return playlists[f->playlist_index];
}

char const *
file_get_metadata(File const *f, enum MetadataX m, char buf[FILE_METADATAX_BUFSZ])
{
	if (m < (enum MetadataX)M_NB)
		return f->metadata[m] ? f->url + f->metadata[m] : NULL;
	else switch (m) {
	case MX_index:
		sprintf(buf, "%"PRId16, f->playlist_order);
		return buf;

	case MX_visual_index:
		sprintf(buf, "%"PRId32, f->index[live]);
		return buf;

	case MX_url:
		return f->url;

	case MX_name:
	{
		char const *p = strrchr(f->url, '/');
		return p && p[1] ? p + 1 : f->url;
	}

	case MX_playlist:
		return file_get_playlist(f)->name;

	default:
		abort();
	}
}

struct timespec
file_get_mtim(File const *f)
{
	struct stat st;
	Playlist *parent = file_get_playlist(f);
	return fstatat(parent->dirfd, f->url, &st, 0)
		? st.st_mtim
		: (struct timespec){ 0 };
}

void
file_free(File *f)
{
	free(f->url);
	free(f);
}
