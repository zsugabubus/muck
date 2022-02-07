#ifndef MUCK_PLAYLIST_H
#define MUCK_PLAYLIST_H

#include <stdint.h>
#include <stdio.h>

#include "error.h"
#include "file.h"

enum {
	PLAYLIST_LINE_MAXSZ =
		sizeof "#EXTINF" +
		M_NB * (METADATA_NAME_MAXSZ + sizeof "=\"\" ") +
		UINT16_MAX +
		(MX_NB - M_NB) + FILE_METADATAX_BUFSZ,
};

typedef struct Playlist {
	File const *f;
	char *name;
	int dirfd;
	char *dirname;
	int16_t index;
	/* Protect user data from unwanted modifications. */
	unsigned read_only: 1;
	unsigned modified: 1;
	int32_t nfiles;
} Playlist;

typedef struct FileReadError {
	Error error;
	size_t lnum;
	size_t col;
	Playlist *playlist;
} FileReadError;

extern int16_t nplaylists;
extern Playlist **playlists;

Playlist *playlist_alloc(File const *f, char const *name);
Playlist *playlist_alloc_master(void);
void playlists_destroy(void);

File *playlist_alloc_file_dupurl(Playlist *parent, enum FileType type, char const *url);
File *playlist_alloc_file(Playlist *parent, enum FileType type, size_t urlsz);

void playlists_save(Error *error);

Playlist *playlist_get_parent(Playlist const *playlist);
void playlist_write_m3u(Playlist *playlist, FILE *stream);

enum FileType playlist_probe_url(Playlist const *parent, char const *url);

void file_read(File *f, FileReadError *error);
void playlist_read(Playlist *playlist, int fd, FileReadError *error);
void playlist_read_m3u(Playlist *playlist, int fd, FileReadError *error);
void playlist_read_dir(Playlist *playlist, FileReadError *error);

#endif
