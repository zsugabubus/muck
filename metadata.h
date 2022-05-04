#ifndef MUCK_METADATA_H
#define MUCK_METADATA_H

#include <limits.h>
#include <stddef.h>

#include "repeat.h"

/**
 * IMPORTANT!
 *
 * - Take care of a sane order to keep key-value pair metadata
 *   searchable even in a simple text editor. Contributors - release - track.
 *
 * - Keep related values together so they can be compressed.
 *
 */
#define METADATA \
	/* xmacro(letter, X, name, def_width, in_url) */ \
	/* Contributors first. */ \
	xmacro('a',, artist, 20, 1) \
	xmacro('A',, album_artist, 25, 1) \
	xmacro('F',, album_featured_artist, 15, 1) \
	xmacro('f',, featured_artist, 15, 1) \
	xmacro('x',, remixer, 15, 1) \
	/* Let barcode be the first album related metadata, since same named \
	 * albums (with matching album related metadata) can appear from \
	 * different contributors. This way remaining metadata stays highly \
	 * compressable even if barcode is different. */ \
	xmacro('B',, barcode, 13, 0) \
	/* Wrap album title between disc/track totals. */ \
	xmacro('d',, disc, 2, 1) \
	xmacro('D',, disc_total, 2, 0) \
	xmacro('T',, album, 25, 1) \
	xmacro('V',, album_version, 15, 1) \
	xmacro('N',, track_total, 2, 0) \
	xmacro('n',, track, 2, 1) \
	/* Similer titles have higher chance to have the same ISRC. */ \
	xmacro('I',, isrc, 12, 0) \
	xmacro('t',, title, 20, 1) \
	xmacro('v',, version, 20, 1) \
	/* Keep genre around bpm. */ \
	xmacro('g',, genre, 35, 0) \
	/* A label used to release in a few genres with near constant bpm. */ \
	xmacro('b',, bpm, 3, 0) \
	xmacro('L',, label, 30, 1) \
	/* Catalog numbers has an alpha prefix that relates to label. Let's put it \
	 * after label. */ \
	xmacro('C',, catalog, 15, 0) \
	xmacro('y',, date, 10, 0) \
	xmacro('o',, codec, 20, 0) \
	xmacro('O',, cover_codec, 10, 0) \
	xmacro('m',, mtime, 10, 0) \
	xmacro('l',, length, 6, 0) \
	xmacro('z',, comment, 20, 0)

/* Extra metadata-like stuff. */
#define METADATAX \
	xmacro('i', X, index, 0, 0) \
	xmacro('k', X, visual_index, 0, 0) \
	xmacro('u', X, name, 30, 1) \
	xmacro('U', X, url, 50, 1) \
	xmacro('p', X, playlist, 15, 0)

#define METADATA_ALL METADATA METADATAX

#define each_metadata(m, set) \
	(enum MetadataX m, loop_ = 1; loop_; loop_ = 0) \
		for (MetadataSet set_ = (set); metadata_iter(&set_, &m);)

enum Metadata {
#define xmacro(letter, X, name, ...) M_##name,
	METADATA
#undef xmacro
	M_NB,
};

enum MetadataX {
	MX_ = M_NB - 1,
#define xmacro(letter, X, name, ...) MX_##name,
	METADATAX
#undef xmacro
	MX_NB,
};

typedef uint64_t MetadataSet;
_Static_assert(MX_NB <= sizeof(MetadataSet) * CHAR_BIT);

static inline char
metadata_get_id(enum MetadataX m)
{
	static char const TABLE[] = {
#define xmacro(letter, ...) letter,
		METADATA_ALL
#undef xmacro
	};

	return TABLE[m];
}

static inline MetadataSet
metadata_to_set(enum MetadataX m)
{
	return (MetadataSet)1 << m;
}

static inline int
metadata_iter(MetadataSet *set, enum MetadataX *m)
{
	if (!*set)
		return 0;

	*m = __builtin_ctz(*set);
	*set ^= metadata_to_set(*m);

	return 1;
}

enum {
	METADATA_NAME_MAXSZ = sizeof(union {
#define xmacro(letter, X, name, ...) char name[sizeof #name - 1];
		METADATA_ALL
#undef xmacro
	}),
};

static inline char const *
metadata_get_name(enum MetadataX m)
{
	static struct Table {
#define xmacro(letter, X, name, ...) \
	char name[M##X##_##name + 1 == MX_NB ? METADATA_NAME_MAXSZ : sizeof #name];
		METADATA_ALL
#undef xmacro
	} const TABLE = {
#define xmacro(letter, X, name, ...) #name,
		METADATA_ALL
#undef xmacro
	};

	typedef uint8_t Offset;

#define O(name) offsetof(struct Table, name)

#define xmacro(letter, X, name, ...) \
	_Static_assert(O(name) == (Offset)O(name), "Offset is too short");
	METADATA_ALL
#undef xmacro

	static Offset const TABLE_OFFSET[] = {
#define xmacro(letter, X, name, ...) O(name),
		METADATA_ALL
#undef xmacro
	};

#undef O

	return ((char const *)&TABLE) + TABLE_OFFSET[m];
}

static inline int
metadata_get_def_width(enum MetadataX m)
{
	static uint8_t const TABLE[] = {
#define xmacro(letter, X, name, def_width, ...) def_width,
		METADATA_ALL
#undef xmacro
	};

	return TABLE[m];
}

static inline int
metadata_parse(enum MetadataX *m, char const c)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"
	static enum MetadataX const TABLE[UINT8_MAX + 1] = {
#define xmacro(i) [i] = MX_NB,
		REPEAT256(0)
#undef xmacro
#define xmacro(letter, X, name, ...) [(uint8_t)letter] = (enum MetadataX)M##X##_##name,
		METADATA_ALL
#undef xmacro
	};
#pragma GCC diagnostic pop

	enum MetadataX ret = TABLE[(uint8_t)c];
	if (MX_NB == ret)
		return 0;
	*m = ret;
	return 1;
}

/* May present in URL if not among tags. */
static MetadataSet const METADATASET_IN_URL =
#define xmacro(letter, X, name, def_width, in_url) +((MetadataSet)in_url << M##X##_##name)
	METADATA_ALL
#undef xmacro
	;

static MetadataSet const METADATASET_NOT_X = ((MetadataSet)1 << M_NB) - 1;
static MetadataSet const METADATASET_IS_X = ~METADATASET_NOT_X;

#endif
