#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

/* FFmpeg. */
#include <libavcodec/avcodec.h>
#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
#include <libavformat/url.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/frame.h>
#include <libswresample/swresample.h>

#include "config.h"

static char const XATTR_COMMENT[] = "user.comment";
static char const XATTR_PLAY_COUNT[] = "user.play_count";
static char const XATTR_SKIP_COUNT[] = "user.skip_count";
static char const XATTR_TAGS[] = "user.tags";

#ifndef NDEBUG
# define xassert(c) assert(c)
#else
# define xassert(c) ((void)(c))
#endif

#define ARRAY_SIZE(x) (sizeof x / sizeof *x)

#define PTR_INC(pp, n) (pp) = (void *)((char *)(pp) + (n))

#define CONTROL(c) ((c) - '@')

#define NS_PER_SEC 1000000000

/* Line-feed that must be used when printing the first line after printing into
 * a dirty terminal line, i.e. after print_progress or editor has been closed. */
#define LF "\e[K\n"
#define CR "\e[K\r"

/* For pipe(). */
enum { R, W, };

enum { CLAUSE_LEVEL_MAX = 10, };

static uint8_t const CACHE_LEVEL_MAX = 8;

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
	/* xmacro(letter, name) */ \
	/* Contributors first. */ \
	xmacro('a', artist) \
	xmacro('A', album_artist) \
	xmacro('F', album_featured_artist) \
	xmacro('f', featured_artist) \
	xmacro('x', remixer) \
	/* Let barcode be the first album related metadata, since same named \
	 * albums (with matching album related metadata) can appear from \
	 * different contributors. This way remaining metadata stays highly \
	 * compressable even if barcode is different. */ \
	xmacro('B', barcode) \
	/* Wrap album title between disc/track totals. */ \
	xmacro('d', disc) \
	xmacro('D', disc_total) \
	xmacro('T', album) \
	xmacro('V', album_version) \
	xmacro('N', track_total) \
	xmacro('n', track) \
	/* Similer titles have higher chance to have the same ISRC. */ \
	xmacro('I', isrc) \
	xmacro('t', title) \
	xmacro('v', version) \
	/* Keep genre around bpm. */ \
	xmacro('g', genre) \
	/* A label used to release in a few genres with near constant bpm. */ \
	xmacro('b', bpm) \
	xmacro('L', label) \
	/* Catalog numbers has an alpha prefix that relates to label. Let's put it \
	 * after label. */ \
	xmacro('C', catalog) \
	xmacro('y', date) \
	xmacro('o', codec) \
	xmacro('c', play_count) /* XXX: c | p | x? */ \
	xmacro('s', skip_count) \
	xmacro('m', mtime) \
	xmacro('h', ptime) /* Last play time. (Last heard.) */ \
	xmacro('d', duration) \
	xmacro('e', user_comment) \
	xmacro('z', tags)

/* Extra metadata-like stuff. */
#define METADATAX \
	xmacro('u', name) \
	xmacro('U', url) \
	xmacro('p', playlist)

#define METADATA_ALL METADATA METADATAX

#define COMPRESSORS \
	/* xmacro(tail, program) */ \
	xmacro(".bz", "bzip2") \
	xmacro(".bz2", "bzip2") \
	xmacro(".gz", "gzip") \
	xmacro(".lz4", "lz4") \
	xmacro(".xz", "xz") \
	xmacro(".zst", "zstd")

static char const METADATA_LETTERS[] = {
#define xmacro(letter, name) letter,
	METADATA_ALL
#undef xmacro
};

static char const METADATA_NAMES[][24] = {
#define xmacro(letter, name) #name,
	METADATA_ALL
#undef xmacro
};

enum Metadata {
#define xmacro(letter, name) M_##name,
	METADATA
#undef xmacro
	M_NB,
};

enum MetadataX {
	MX_ = M_NB - 1,
#define xmacro(letter, name) MX_##name,
	METADATAX
#undef xmacro
	MX_NB,
};

_Static_assert(MX_NB <= 64);

enum FileType {
	/* Files have metadata. */
	F_URL, /**< Not prefixed by */
	F_FILE, /**< Handled by FFmpeg. */

	/* Containers. */
	F_PLAYLIST, /**< Handled by us. */
	F_PLAYLIST_COMPRESSED,
	F_PLAYLIST_DIRECTORY,
};

typedef struct {
	enum FileType type: CHAR_BIT;
	enum FileType prev_type: CHAR_BIT;
	uint32_t filter_mask;
	char *url; /* URL "\0" [METADATA-VALUE [";" METADATA-VALUE]... "\0"]... */
} AnyFile;

typedef struct {
	AnyFile a;
	uint16_t metadata[M_NB]; /* x => url + metadata[x]; 0 if key not present. */
} File;

typedef struct Playlist Playlist;
struct Playlist {
	AnyFile a;
	int dirfd;
	/* Protect user data from unwanted modifications. */
	unsigned read_only: 1;
	unsigned modified: 1;
	char mnemonic;
	enum FileType last_child_type: CHAR_BIT; /* For backwards interating. */
	size_t files_size;
	AnyFile *files;
	Playlist *parent;
	char *name;
	size_t next_sibling_playlist;
	size_t first_child_playlist;
	uint64_t child_filter_count[32];
};

#define for_each_file(const) \
	for (size_t offset = 0; offset < playlist->files_size;) \
		for (AnyFile const *a = (void *)((char *)playlist->files + offset); a; offset += get_file_size(a->type), a = NULL)

#define for_each_playlist(playlist, parent) \
	for (Playlist *playlist = SIZE_MAX == parent->first_child_playlist ? NULL : (void *)((char *)parent->files + parent->first_child_playlist); \
	     playlist; \
	     playlist = SIZE_MAX == playlist->next_sibling_playlist ? NULL : (void *)((char *)playlist + playlist->next_sibling_playlist))

typedef struct {
	Playlist *p;
	File *f;
} PlaylistFile;

typedef struct {
	AVFormatContext *format_ctx;
	AVCodecContext *codec_ctx;
	AVStream *audio;
} Stream;

typedef struct {
	Stream s;
	AVAudioFifo *fifo;
	int64_t cur_frame;
	int64_t next_pts;

	int fifo_stopped;
	/* Whenever FIFO accessed. */
	pthread_mutex_t fifo_mutex;
	/* Whenever FIFO buffer changes. Also used for signalling seeking/track
	 * change. */
	pthread_cond_t fifo_cond;

	/* To avoid excessive read of files after seeking, we do not demux the
	 * whole file in advance but at most 2**cache_level seconds in
	 * advance. */
	uint8_t cache_level;
	/* How many samples have been decoded since cache_level changed last time? */
	uint64_t cache_counter;
} Output;

typedef struct {
	Stream s;
	AVStream *cover_front;
	SwrContext *resampler;
	PlaylistFile pf;
	int fd;
} Input;

static int64_t master_pts = AV_NOPTS_VALUE;
static Output cur_out;
static Input cur_in = {
	.fd = -1,
};
/* Protect cur_{in,out}. */
static pthread_rwlock_t cur_rwlock; /* > FIFO lock */

static int paused;
static int sought;

static int term_height;

static int control[2];

static char next_cmd = 'n';

static FILE *tty;

struct termios saved_termios;
static Playlist master;

/* Index of current filter in .[live]. */
static uint8_t cur_filter[2];

/* TODO: Queue is live queue has p=^queue$ filter. In non-live mode we can select tracks etc. */
static int live = 1;

static int has_number = 0;
static int64_t cur_number;

static int auto_w = 0, auto_i = 0;

static char *last_search;

static char const *output_name = "alsa";
static int debug;
static int writable;

static int threads_inited;
static pthread_t source_thread, sink_thread;

#define IS_SUFFIX(lit) \
	((sizeof lit - 1) <= url_size && \
	 !memcmp(url + url_size - (sizeof lit - 1), lit, (sizeof lit - 1)) && \
	 (url_size -= (sizeof lit - 1), 1))

/**
 * xorshift* context.
 *
 * @see https://en.wikipedia.org/wiki/Xorshift
 */
typedef union {
	struct {
		uint64_t a, b;
	};
	uint8_t bytes[16];
} RndState;

static RndState rnd;

static int
rnd_init(RndState *state)
{
	int fd = open("/dev/random", O_CLOEXEC | O_EXCL | O_RDONLY);
	if (fd < 0)
		return -1;

	int rc = 0;

	do {
		size_t rem = sizeof state->bytes;
		do {
			ssize_t got = read(fd, (&state->bytes)[1] - rem, rem);
			if (got < 0) {
				rc = -errno;
				goto out;
			} else if (!got) {
				rc = -EBADF;
				goto out;
			}
			rem -= got;
		} while (rem);
		/* Ensure not all zero. */
	} while (!(state->a | state->b));

out:
	close(fd);

	return rc;
}

/** Generate a good random number in range [0..UINT64_MAX]. */
static uint64_t
rnd_next(RndState *state)
{
	uint64_t t = state->a;
	uint64_t s = state->b;
	state->a = s;
	t ^= t << 23;
	t ^= t >> 17;
	t ^= s ^ (s >> 26);
	state->b = t;
	return t + s;
}

/**
 * Generate a uniform random number in range [0..n).
 */
static uint64_t
rndn(RndState *state, uint64_t n)
{
	uint64_t rem = UINT64_MAX % n;
	uint64_t x;
	while ((x = rnd_next(state)) < rem);
	return (x - rem) % n;
}

static char const *
get_playlist_name(Playlist const *playlist)
{
	return playlist->name ? playlist->name : playlist->a.url;
}

static void
print_file_error(Playlist const *parent, AnyFile const *a, char const *message, char const *error_msg)
{
	flockfile(tty);
	fputs("\e[1;31m", tty);
	if (parent)
		fprintf(tty, "%s/", get_playlist_name(parent));
	char const *url = ((AnyFile const *)a)->url;
	fprintf(tty, "%s: %s", url ? url : "(none)", message);
	if (error_msg)
		fprintf(tty, ": %s", error_msg);
	fputs("\e[m\n", tty);
	funlockfile(tty);
}

static void
print_file_averror(Playlist const *parent, AnyFile const *a, char const *message, int err)
{
	print_file_error(parent, a, message, av_err2str(err));
}

static void
print_file_strerror(Playlist const *parent, AnyFile const *a, char const *message)
{
	print_file_error(parent, a, message, strerror(errno));
}

static enum FileType
probe_url(Playlist const *parent, char const *url)
{
	URLComponents uc;
	if (0 <= ff_url_decompose(&uc, url, NULL) &&
	    uc.scheme < uc.path)
		return F_URL;

	if (parent) {
		struct stat st;
		if (0 <= fstatat(parent->dirfd, url, &st, 0) &&
		    S_ISDIR(st.st_mode))
			return F_PLAYLIST_DIRECTORY;
	}

	size_t url_size = strlen(url);

#define xmacro(tail, program) || IS_SUFFIX(tail)
	enum FileType playlist_type = 0 COMPRESSORS
		? F_PLAYLIST_COMPRESSED
		: F_PLAYLIST;
#undef xmacro

	return
		IS_SUFFIX(".m3u") ||
		IS_SUFFIX(".m3u8") ||
		IS_SUFFIX(".pl")
		? playlist_type
		: F_FILE;
}

static char const *
probe_compressor(char const *url)
{
	size_t url_size = strlen(url);

#define xmacro(tail, program) if (IS_SUFFIX(tail)) return program;
	COMPRESSORS
#undef xmacro

	abort();
}

#undef IS_SUFFIX

static void
fd2dirname(int fd, char dirbuf[static PATH_MAX])
{
	ssize_t size;

	if (AT_FDCWD != fd) {
		char linkname[50];
		sprintf(linkname, "/proc/self/fd/%d", fd);
		size = readlink(linkname, dirbuf, PATH_MAX - 2);
	} else
		size = getcwd(dirbuf, PATH_MAX) ? strlen(dirbuf) : 0;

	if (0 <= size) {
		dirbuf[size] = '/';
		dirbuf[size + 1] = '\0';
	} else {
		sprintf(dirbuf, "(error)/");
	}
}

static size_t
get_file_size(enum FileType type)
{
	return F_FILE < type ? sizeof(Playlist) : sizeof(File);
}

static void
plumb_file_(AnyFile const *a, char const *dirname, uint8_t filter_index, FILE *stream)
{
	if (a->type <= F_FILE) {
		File const *f = (void *)a;
		if (!(f->a.filter_mask & (UINT32_C(1) << filter_index)))
			return;

		if (F_FILE == f->a.type &&
		    '/' != *f->a.url)
			fputs(dirname, stream);
		fputs(f->a.url, stream);

		for (enum Metadata m = 0; m < M_NB; ++m) {
			fputc('\t', stream);
			if (f->metadata[m])
				fputs(f->a.url + f->metadata[m], stream);
		}

		fputc('\n', stream);
	} else {
		Playlist const *playlist = (void *)a;
		char dirbuf[PATH_MAX];
		fd2dirname(playlist->dirfd, dirbuf);

		for_each_file()
			plumb_file_(a, dirbuf, filter_index, stream);
	}
}

static void
plumb_file(AnyFile const *a, uint8_t filter_index, FILE *stream)
{
	fputs("path", stream);
	for (enum Metadata m = 0; m < M_NB; ++m) {
		fputc('\t', stream);
		fputs(METADATA_NAMES[m], stream);
	}
	fputc('\n', stream);

	plumb_file_(a, NULL, filter_index, stream);
}

static void
cleanup_file(AnyFile *a)
{
	free(a->url);
	if (F_FILE < a->type) {
		Playlist *playlist = (void *)a;
		if (0 <= playlist->dirfd)
			close(playlist->dirfd);
		free(playlist->name);
		for_each_file()
			cleanup_file(a);
		free(playlist->files);
	}
}

static void *
append_file(Playlist *parent, enum FileType type)
{
	size_t append_size = get_file_size(type);

	size_t new_files_size = parent->files_size + append_size;
	/* Check whether highest bit set is greater than before. If so it, it
	 * means that we have exceeded current allocation boundary. */
	if ((new_files_size ^ parent->files_size) > parent->files_size) {
		void *p = realloc(parent->files, new_files_size * 2);
		if (!p) {
			print_file_strerror(parent->parent, &parent->a, "Could not append file to playlist");
			exit(EXIT_FAILURE);
		}
		void *old_files = parent->files;
		parent->files = p;

		/* Update parent references. */
		if (old_files != parent->files)
			for_each_playlist(child_playlist, parent)
				for_each_playlist(grandchild_playlist, child_playlist)
					PTR_INC(grandchild_playlist->parent, (char *)parent->files - (char *)old_files);
	}

	AnyFile *a = (void *)((char *)parent->files + parent->files_size);

	a->prev_type = parent->last_child_type;
	parent->last_child_type = type;

	a->url = NULL;
	a->type = type;
	a->filter_mask = 1;
	if (F_FILE < a->type) {
		if (SIZE_MAX == parent->first_child_playlist)
			parent->first_child_playlist = parent->files_size;
		else {
			Playlist *p = (void *)((char *)parent->files + parent->first_child_playlist);
			assert(F_FILE < p->a.type);
			while (SIZE_MAX != p->next_sibling_playlist)
				PTR_INC(p, p->next_sibling_playlist);
			p->next_sibling_playlist = (char *)a - (char *)p;
		}

		Playlist *playlist = (void *)a;
		playlist->parent = parent;
		playlist->first_child_playlist = SIZE_MAX;
		playlist->next_sibling_playlist = SIZE_MAX;
		memset(playlist->child_filter_count, 0, sizeof playlist->child_filter_count);

		playlist->dirfd = -1;
		playlist->read_only = 0;
		playlist->modified = 0;
		playlist->files_size = 0;
		playlist->files = NULL;
		playlist->name = NULL;
	} else {
		Playlist *p = parent;
		do
			++p->child_filter_count[0];
		while ((p = p->parent));
	}

	parent->files_size = new_files_size;

	return a;
}

static void
print_playlist_error(Playlist const *playlist, int color, char const *msg, size_t lnum, size_t col)
{
	flockfile(tty);
	fprintf(tty, "\e[1;%dm", color);
	fputs(get_playlist_name(playlist), tty);
	fputs(":", tty);
	if (lnum) {
		fprintf(tty, "%zu:", lnum);
		if (col)
			fprintf(tty, "%zu:", col);
	}
	fprintf(tty, " %s\e[m\n", msg);
	funlockfile(tty);
}

static void
read_file(Playlist *parent, AnyFile *a);

static void
read_playlist(Playlist *playlist, int fd)
{
	char const *error_msg = NULL;

	File file;
	char file_data[UINT16_MAX];
	size_t file_data_size = 0;

	char buf[UINT16_MAX]; /* NOTE: In theory a line could be longer. */
	uint16_t buf_size = 0;

	int is_m3u = 0;

	size_t lnum = 1;
	char *col;

	for (;;) {
		col = NULL;

		char *line_end;
		while (!(line_end = memchr(buf, '\n', buf_size))) {
			if (sizeof buf == buf_size) {
				error_msg = "Line length exceeds maximum limit";
				goto out;
			}

			ssize_t len = read(fd, buf + buf_size, sizeof buf - buf_size);
			if (len < 0) {
			fail_strerror:
				error_msg = strerror(errno);
				goto out;
			} else if (!len)
				/* Last line must be LF terminated. */
				goto out;

			buf_size += len;
		}

		char *line = buf;
		*line_end = '\0';

		if (1 == lnum && !strcmp(line, "#EXTM3U")) {
			is_m3u = 1;
			goto reset_file;
		} else if (is_m3u && '#' == *line) {
#define IS_DIRECTIVE(directive) \
	(!memcmp(line + 1, directive, strlen(directive)) && \
	 (col = line + 1 + strlen(directive)))

			if (IS_DIRECTIVE("EXTINF:")) {
				for (enum Metadata m = 0; m < M_NB; ++m)
					file.metadata[m] = UINT16_MAX;
				file_data_size = 0;

				file.metadata[M_duration] = 0;
				while ('0' <= *col && *col <= '9') {
					if (sizeof file_data <= file_data_size) {
					fail_too_long:
						error_msg = "Too much data";
						goto out;
					}
					file_data[file_data_size++] = *col++;
				}
				file_data[file_data_size++] = '\0';

				for (;;) {
					while (' ' == *col)
						++col;

					if (',' == *col) {
						++col;
						break;
					} else if (!*col) {
						error_msg = "Expected , or parameter name";
						goto out;
					}

					char *equal = strchr(col, '=');
					if (!equal) {
						error_msg = "Expected = after parameter name";
						goto out;
					}
					*equal = '\0';

					enum Metadata m;
					for (m = 0; m < M_NB; ++m)
						if (!strcmp(col, METADATA_NAMES[m]))
							break;

					switch (m) {
					case M_NB:
					/* Supplied in another way. */
					case M_duration:
						error_msg = "Unknown parameter";
						goto out;

					default:;
					}
					col = equal + 1;

					if ('"' != *col) {
						error_msg = "Expected \" after =";
						goto out;
					}
					++col;

					file.metadata[m] = file_data_size;
					for (;;) {
						if ('"' == *col) {
							++col;
							break;
						}

						col += '\\' == *col;
						if (!*col) {
							error_msg = "Unterminated \"";
							goto out;
						}

						if (sizeof file_data <= file_data_size)
							goto fail_too_long;
						file_data[file_data_size++] = *col++;
					}
					file_data[file_data_size++] = '\0';
				}

				if (*col) {
					/* We use structured parameters instead of title. */
					error_msg = "Trailing characters"; /* Fuck users, live long Vim. */
					goto out;
				}
			} else if (IS_DIRECTIVE("EXT-X-BASE-URL:")) {
				if (playlist->files_size) {
				fail_used_too_late:
					error_msg = "Directive may only be used before media URLs";
					goto out;
				}

				close(playlist->dirfd);
				playlist->dirfd = openat(
						playlist->parent ? playlist->parent->dirfd : AT_FDCWD,
						col,
						O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);
				/* NOTE: Only plain directory base URLs are supported. */
				if (playlist->dirfd < 0)
					goto fail_strerror;
			} else if (IS_DIRECTIVE("PLAYLIST:")) {
				if (playlist->files_size)
					goto fail_used_too_late;

				free(playlist->name);
				if (!(playlist->name = strdup(col))) {
					print_file_strerror(playlist->parent, &playlist->a, "Could not allocate playlist name");
					exit(EXIT_FAILURE);
				}
			} else if (IS_DIRECTIVE("EXT")) {
				playlist->read_only = 1;
				print_playlist_error(playlist, 0, "Unknown directive", lnum, 0);
			} else if (!playlist->read_only) {
				playlist->read_only = 1;
				print_playlist_error(playlist, 0, "Unknown comment", lnum, 0);
			}

#undef IS_DIRECTIVE
		} else if (*line) {

			char const *url = line;
			size_t url_size = line_end - line + 1 /* NUL */;

			if (sizeof file_data < url_size + file_data_size)
				goto fail_too_long;

			enum FileType type = probe_url(NULL, url);
			AnyFile *a = append_file(playlist, type);
			if (a->type <= F_FILE) {
				File *f = (void *)a;
				for (enum Metadata m = 0; m < M_NB; ++m)
					f->metadata[m] = UINT16_MAX != file.metadata[m]
						? url_size + file.metadata[m]
						: 0;
			} else {
				file_data_size = 0;
			}

			if (!(a->url = malloc(url_size + file_data_size)))
				exit(ENOMEM);
			memcpy(a->url, url, url_size);
			memcpy(a->url + url_size, file_data, file_data_size);

			read_file(playlist, a);

		reset_file:;
			for (enum Metadata m = 0; m < M_NB; ++m)
				file.metadata[m] = UINT16_MAX;
			file_data_size = 0;
		}

		++line_end; /* Skip LF. */
		buf_size -= line_end - buf;
		memmove(buf, line_end, buf_size);
		++lnum;
	}

out:
	if (error_msg) {
		print_playlist_error(playlist, 31, error_msg, lnum, col ? col - buf + 1 : 0);
		/* Try do our best, so just mark it as read-only. This avoids
		 * writing back any faulty data. */
		playlist->read_only = 1;
	}

	if (playlist->read_only)
		print_playlist_error(playlist, 0, "Opened read-only", 0, 0);

	close(fd);
}

static void
init_file(AnyFile *a, char const *url)
{
	if (!(a->url = strdup(url))) {
		print_file_strerror(NULL, a, "Could not allocate URL");
		exit(EXIT_FAILURE);
	}

	if (a->type <= F_FILE) {
		File *f = (void *)a;
		memset(f->metadata, 0, sizeof f->metadata);
	}
}

static void
read_playlist_directory(Playlist *playlist, int fd)
{
	playlist->dirfd = fd;
	playlist->read_only = 1;

	DIR *dir = fdopendir(dup(playlist->dirfd));
	if (!dir)
		return;

	for (struct dirent *dent; (dent = readdir(dir));) {
		char const *name = dent->d_name;
		/* Skip files starting with dot. */
		if ('.' == *name)
			continue;

		enum FileType type = probe_url(NULL, name);
		AnyFile *a = append_file(playlist, type);
		init_file(a, name);
		read_file(playlist, a);
	}

	closedir(dir);
}

static int
open_file(Playlist *parent, AnyFile *a)
{
	int fd = openat(parent->dirfd, a->url, O_CLOEXEC | O_RDONLY);
	if (fd < 0) {
		print_file_strerror(parent, a, "Could not open file");
		return -1;
	}

	return fd;
}

static Playlist *
find_playlist_by_mnemonic(Playlist *playlist, char c)
{
	if (c == playlist->mnemonic)
		return playlist;

	for_each_playlist(child_playlist, playlist) {
		Playlist *ret = find_playlist_by_mnemonic(child_playlist, c);
		if (ret)
			return ret;
	}

	return NULL;
}

static void
read_file(Playlist *parent, AnyFile *a)
{
	if (a->type <= F_FILE)
		return;

	Playlist *playlist = (void *)a;

	assert(!playlist->files_size);

	int fd = open_file(parent, a);
	if (fd < 0)
		return;

	if (F_PLAYLIST == playlist->a.type ||
	    F_PLAYLIST_COMPRESSED == playlist->a.type)
	{
		if (F_PLAYLIST_COMPRESSED == playlist->a.type) {
			int pipes[2] = { -1, -1 };
			pid_t pid;

			if (pipe2(pipes, O_CLOEXEC) < 0 ||
			    (pid = fork()) < 0)
			{
				print_file_strerror(playlist, a, "Could not decompress playlist");
				if (0 <= pipes[R]) {
					close(pipes[R]);
					close(pipes[W]);
				}
				close(fd);
				return;
			} else if (!pid) {
				char const *program = probe_compressor(playlist->a.url);
				if (close(pipes[R]) < 0 ||
				    dup2(fd, STDIN_FILENO) < 0 ||
				    close(fd) < 0 ||
				    dup2(pipes[W], STDOUT_FILENO) < 0 ||
				    close(pipes[W]) < 0 ||
				    execlp(program, program, "-d", "-c", NULL) < 0)
					print_file_strerror(playlist, a, "Could not decompress playlist");
				_exit(127);
			} else {
				close(fd);
				fd = pipes[R];
				close(pipes[W]);
			}
		}

		char *slash = strrchr(playlist->a.url, '/');
		if (slash)
			*slash = '\0';

		char const *dirname = slash ? playlist->a.url : ".";

		playlist->dirfd = openat(parent->dirfd, dirname,
				O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);
		if (playlist->dirfd < 0)
			return;

		if (slash)
			*slash = '/';

		read_playlist(playlist, fd);
	} else if (F_PLAYLIST_DIRECTORY == playlist->a.type) {
		read_playlist_directory(playlist, fd);
	} else {
		abort();
	}

	for (char const **ps = (char const *[]){
		playlist->name,
		strrchr(playlist->a.url, '/'),
		playlist->a.url,
		"0123456789",
		NULL,
	}; *ps; ++ps)
		for (char const *s = *ps; *s; ++s)
			if ((('a' <= *s && *s <= 'z') ||
			     ('A' <= *s && *s <= 'Z') ||
			     ('0' <= *s && *s <= '9')) &&
			    !find_playlist_by_mnemonic(&master, *s))
			{
				playlist->mnemonic = *s;
				break;
			}
}

static void
write_playlist(Playlist *playlist, FILE *stream)
{
	fprintf(stream, "#EXTM3U\n");
	if (playlist->name)
		fprintf(stream, "#PLAYLIST:%s\n", playlist->name);

	for_each_file() {
		if (a->type <= F_FILE) {
			File const *f = (void *)a;

			int any = 0;
			for (enum Metadata m = 0; m < M_NB; ++m) {
				if (!f->metadata[m])
					continue;
				if (M_duration == m)
					continue;

				if (!any)
					fprintf(stream, "#EXTINF:%s",
							f->metadata[M_duration]
								? f->a.url + f->metadata[M_duration]
								: "");

				fprintf(stream, " %s=\"", METADATA_NAMES[m]);
				for (char const *c = f->a.url + f->metadata[m];
				     *c;
				     ++c)
				{
					if ('"' == *c || '\\' == *c)
						fputc('\\', stream);
					fputc(*c, stream);
				}
				fputc('"', stream);

				any = 1;
			}

			if (any)
				fputs(",\n", stream);
		}
		fprintf(stream, "%s\n", a->url);
	}
}

static void
save_playlist(Playlist *playlist)
{
	for_each_playlist(child_playlist, playlist)
		save_playlist(child_playlist);

	if (/* Should not be modified. */
	    playlist->read_only ||
	    !playlist->modified ||
	    /* Not opened. */
	    !playlist->files)
		return;

	fprintf(tty, "Saving %s..."CR, playlist->a.url);
	fflush(tty);

	char tmp_pathname[PATH_MAX];

	int n = snprintf(tmp_pathname, sizeof tmp_pathname,
			"%s~", playlist->a.url);
	if ((int)sizeof tmp_pathname <= n) {
		errno = ENAMETOOLONG;
		goto fail_strerror;
	}

	int dirfd = playlist->parent ? playlist->parent->dirfd : AT_FDCWD;
	int fd = openat(dirfd,
			tmp_pathname,
			O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (fd < 0) {
	fail_strerror:
		print_file_strerror(playlist->parent, &playlist->a, "Could not open temporary file");
		return;
	}

	if (F_PLAYLIST == playlist->a.type) {
		/* Nothing to do. */
	} else if (F_PLAYLIST_COMPRESSED == playlist->a.type) {
		int pipes[2] = { -1, -1 };

		pid_t pid;
		if (pipe2(pipes, O_CLOEXEC) < 0 ||
		    (pid = fork()) < 0)
		{
			print_file_strerror(playlist->parent, &playlist->a, "Could not compress playlist");
			if (0 <= pipes[R]) {
				close(pipes[R]);
				close(pipes[W]);
			}
			return;
		} else if (!pid) {
			char const *program = probe_compressor(playlist->a.url);
			if (close(pipes[W]) < 0 ||
			    dup2(pipes[R], STDIN_FILENO) < 0 ||
			    close(pipes[R]) < 0 ||
			    dup2(fd, STDOUT_FILENO) < 0 ||
			    close(fd) < 0 ||
			    execlp(program, program, "-c", NULL) < 0)
				print_file_strerror(playlist->parent, &playlist->a, "Could not compress playlist");
			_exit(127);
		} else {
			close(pipes[R]);
			fd = pipes[W];
		}
	} else {
		abort();
	}

	FILE *stream = fdopen(fd, "w");
	if (!stream) {
		print_file_strerror(playlist->parent, &playlist->a, "Could not open playlist stream");
		return;
	}

	char buf[UINT16_MAX + 1];
	setbuffer(stream, buf, sizeof buf);

	write_playlist(playlist, stream);

	fflush(stream);
	if (ferror(stream)) {
		print_file_strerror(playlist->parent, &playlist->a, "Could not write playlist");
		fclose(stream);
		unlink(tmp_pathname);
		return;
	}
	fclose(stream);

	if (renameat(dirfd, tmp_pathname, dirfd, playlist->a.url) < 0) {
		unlink(tmp_pathname);
		print_file_strerror(playlist->parent, &playlist->a, "Could not replace existing playlist");
		return;
	}
}

static void
close_output(Output *out)
{
	if (out->s.format_ctx) {
		int rc = av_write_trailer(out->s.format_ctx);
		if (rc < 0) {
			av_log(out->s.format_ctx, AV_LOG_ERROR,
					"Could not write output file trailer: %s\n",
					av_err2str(rc));
		}
	}

	if (out->s.codec_ctx)
		avcodec_free_context(&out->s.codec_ctx);
	if (out->s.format_ctx) {
		avio_closep(&out->s.format_ctx->pb);
		avformat_free_context(out->s.format_ctx);
	}

	av_audio_fifo_free(out->fifo);
}

static void
close_input(Input *in)
{
	if (in->s.codec_ctx)
		avcodec_free_context(&in->s.codec_ctx);
	if (in->s.format_ctx) {
		avio_closep(&in->s.format_ctx->pb);
		avformat_close_input(&in->s.format_ctx);
	}
	if (0 <= in->fd)
		close(in->fd);
}

static int
read_xattr(Input const *in, File *tmpf, char *file_data, size_t *pfile_data_size, char const *xname, enum Metadata xm)
{
	size_t max = (UINT16_MAX - 1 /* NUL */) - *pfile_data_size;
	ssize_t size = fgetxattr(in->fd, xname, file_data + *pfile_data_size, max);
	if (0 < size) {
		if (max <= (size_t)size)
			return -ENOSPC;

		tmpf->metadata[xm] = *pfile_data_size;
		file_data[*pfile_data_size + size] = '\0';
		*pfile_data_size += size + 1 /* NUL */;
	}

	return 0;
}

static void
sanitize_metadata_count(File *f, enum Metadata count, enum Metadata total)
{
	if (!f->metadata[count])
		return;

	char *p = strchr(f->a.url + f->metadata[count], '/');
	if (p) {
		*p = '\0';
		if (!f->metadata[total])
			f->metadata[total] = (p + 1 /* Over /. */) - f->a.url;
	}
}

static void
sanitize_metadata(File *f)
{
	sanitize_metadata_count(f, M_disc, M_disc_total);
	sanitize_metadata_count(f, M_track, M_track_total);

	static enum Metadata const TRIM_ZEROS[] = {
		M_disc,
		M_disc_total,
		M_track,
		M_track_total,
	};

	for (size_t i = 0; i < ARRAY_SIZE(TRIM_ZEROS); ++i) {
		enum Metadata m = TRIM_ZEROS[i];
		if (f->metadata[m]) {
			char c;
			while ('0' == (c = f->a.url[f->metadata[m]]))
				++f->metadata[m];
			if (!c)
				f->metadata[m] = 0;
		}
	}
}

static void
read_metadata(Input const *in)
{
	typedef struct {
		enum Metadata metadata;
		char const *tags;
	} MetadataMapEntry;

	static MetadataMapEntry const METADATA_MAP[] = {

		{ M_album, "album\0" },
		{ M_album_artist, "album_artist\0" },
		{ M_album_featured_artist, "ALBUM/FEATURED_ARTIST\0" },
		{ M_album_version, "album_version\0" "ALBUM/VERSION\0" },
		{ M_artist, "artist\0" "ARTISTS\0" },
		{ M_barcode, "BARCODE\0" "UPC\0" "EAN\0" },
		{ M_date, "date_released\0" "date\0" "date_published\0" "TYER\0" },
		{ M_disc, "disc\0" },
		{ M_disc_total, "disc_total\0" },
		{ M_featured_artist, "TRACK/FEATURED_ARTIST\0" },
		{ M_genre, "genre\0" },
		{ M_isrc, "isrc\0" "TSRC\0" },
		{ M_label, "ALBUM/LABEL\0" "label\0" },
		{ M_title, "title\0" "tit1\0" },
		{ M_track, "track\0" },
		{ M_track_total, "track_total\0" },
		{ M_version, "TRACK/VERSION\0" "version\0" },

	};

	AVDictionary const *m = in->s.format_ctx->metadata;
	Playlist *playlist = in->pf.p;
	File *f = in->pf.f;

	File tmpf;
	char file_data[UINT16_MAX];

	/* Begin file data with its URL. */
	size_t url_size = strlen(f->a.url) + 1 /* NUL */;
	size_t file_data_size = url_size;

	for (enum Metadata m = 0; m < M_NB; ++m)
		tmpf.metadata[m] = 0;

	/* Append duration. */
	int64_t duration = in->s.format_ctx->duration;
	if (AV_NOPTS_VALUE != duration) {
		if (UINT16_MAX < file_data_size + (1 + 20 + 1)) {
		fail_too_long:
			print_file_error(playlist, &f->a, "Too much metadata", NULL);
			return;
		}

		tmpf.metadata[M_duration] = file_data_size;
		file_data_size += sprintf(file_data + file_data_size, "%"PRId64,
				duration / AV_TIME_BASE) + 1 /* NUL */;
	}

	struct stat st;
	if (0 <= in->fd && 0 <= fstat(in->fd, &st)) {
		/* Append mtime. */
		if (UINT16_MAX < file_data_size + sizeof "0000-00-00")
			goto fail_too_long;

		tmpf.metadata[M_mtime] = file_data_size;
		file_data_size += strftime(file_data + file_data_size, 11, "%F",
				gmtime(&(time_t){ st.st_mtime })) + 1 /* NUL */;
	}

	/* Append codec. */
	char buf[128];
	av_get_channel_layout_string(buf, sizeof buf,
			in->s.codec_ctx->channels, in->s.codec_ctx->channel_layout);
	int n = snprintf(file_data + file_data_size, UINT16_MAX - file_data_size,
			"%s-%s-%d",
			in->s.codec_ctx->codec->name,
			buf,
			in->s.codec_ctx->sample_rate / 1000);
	if (UINT16_MAX <= file_data_size + n)
		goto fail_too_long;
	tmpf.metadata[M_codec] = file_data_size;
	file_data_size += n + 1 /* NUL */;

	for (MetadataMapEntry const *e = METADATA_MAP;
	     e < (&METADATA_MAP)[1];
	     ++e)
	{
		for (char const *key = e->tags;
		     *key;
		     key += strlen(key) + 1 /* NUL */)
		{
			int any = 0;
			for (AVDictionaryEntry const *t = NULL;
			     (t = av_dict_get(m, key, t, 0));)
			{
				char const *src = t->value;
				while ((unsigned char)*src <= ' ')
					++src;

				size_t n = strlen(src) + 1 /* NUL */;

				if (UINT16_MAX < file_data_size + n)
					goto fail_too_long;

				if (!any)
					tmpf.metadata[e->metadata] = file_data_size;
				else
					file_data[file_data_size - 1] = ';';

				char *dest = file_data + file_data_size;
				file_data_size += n;

				int err = 0;
				for (; --n; ++dest, ++src) {
					if ((unsigned char)*src < ' ') {
						err = 1;
						*dest = ' ';
					} else {
						*dest = *src;
					}
				}

				if (err)
					print_file_strerror(playlist, &f->a, "Metadata contains control character");

				while (' ' == dest[-1])
					--dest;

				*dest = '\0';

				any = 1;
			}

			if (any)
				break;
		}
	}

	if (read_xattr(in, &tmpf, file_data, &file_data_size, XATTR_COMMENT, M_user_comment) < 0 ||
	    read_xattr(in, &tmpf, file_data, &file_data_size, XATTR_PLAY_COUNT, M_play_count) < 0 ||
	    read_xattr(in, &tmpf, file_data, &file_data_size, XATTR_SKIP_COUNT, M_skip_count) < 0 ||
	    read_xattr(in, &tmpf, file_data, &file_data_size, XATTR_TAGS, M_tags) < 0)
		goto fail_too_long;

	if (!playlist->modified) {
		for (enum Metadata m = 0; m < M_NB; ++m)
			if (!!tmpf.metadata[m] != !!f->metadata[m] ||
			    (tmpf.metadata[m] &&
			     strcmp(file_data + tmpf.metadata[m], f->a.url + f->metadata[m])))
				goto changed;
		return;
	changed:
	}

	void *p;
	if (!(p = malloc(file_data_size)))
		goto fail_too_long;

	playlist->modified = 1;

	memcpy(p, f->a.url, url_size);
	memcpy(p + url_size, file_data + url_size, file_data_size - url_size);

	free(f->a.url);
	f->a.url = p;

	memcpy(f->metadata, tmpf.metadata, sizeof tmpf.metadata);
	sanitize_metadata(f);
}

static char const *
get_config_path(char const *filename)
{
	static char pathname[PATH_MAX];
	snprintf(pathname, sizeof pathname, "%s/%s",
			getenv("MUCK_HOME"), filename);
	return pathname;
}

static void
update_cover(Input const *in)
{
	char const *pathname = get_config_path("cover");
	int fd = open(pathname,
			O_CLOEXEC |
			O_RDWR | /* Shared mmap() requires it. */
			O_TRUNC);
	if (fd < 0)
		return;

	void *p;
	uint8_t const *data;
	int data_size;

	if (in->cover_front) {
		data = in->cover_front->attached_pic.data;
		data_size = in->cover_front->attached_pic.size;
	} else {
		static uint8_t const
		DEFAULT_COVER[] =
		{
#include "cover.png.h"
		};

		data = DEFAULT_COVER;
		data_size = sizeof DEFAULT_COVER;
	}

	ftruncate(fd, data_size);
	if (MAP_FAILED != (p = mmap(NULL, data_size, PROT_WRITE, MAP_SHARED, fd, 0))) {
		memcpy(p, data, data_size);
		munmap(p, data_size);
	} else {
		ftruncate(fd, 0);
	}

	/* Notify programs about changing. */
	futimens(fd, NULL /* Now. */);

	close(fd);
}

static int
open_input(Input *in)
{
	memset(&in->s, 0, sizeof in->s);

	char const *url;
	char urlbuf[sizeof "pipe:" + 10];

	Playlist *playlist = in->pf.p;
	File *f = in->pf.f;

	if (F_URL == f->a.type) {
		in->fd = -1;
		url = f->a.url;
	} else {
		in->fd = open_file(playlist, &f->a);
		if (in->fd < 0)
			return -1;
		sprintf(urlbuf, "pipe:%d", in->fd);
		url = urlbuf;
	}

	int rc;

	rc = avformat_open_input(&in->s.format_ctx, url, NULL, NULL);
	if (rc < 0) {
		print_file_averror(playlist, &f->a, "Could not open input stream", rc);
		return -1;
	}

	/* Get information on the input file (number of streams etc.). */
	(void)avformat_find_stream_info(in->s.format_ctx, NULL);

	in->cover_front = NULL;
	in->s.audio = NULL;
	for (unsigned i = 0; i < in->s.format_ctx->nb_streams; ++i) {
		AVStream *stream = in->s.format_ctx->streams[i];
		if (AVMEDIA_TYPE_AUDIO == stream->codecpar->codec_type) {
			if (in->s.audio)
				fprintf(tty, "File contains multiple audio tracks. Use t to switch to another.\n");
			in->s.audio = stream;
		} else if ((AV_DISPOSITION_ATTACHED_PIC & stream->disposition) &&
		           AVMEDIA_TYPE_VIDEO == stream->codecpar->codec_type)
		{
			AVDictionaryEntry const *title = av_dict_get(stream->metadata, "comment", NULL, 0);
			if (!title)
				title = av_dict_get(stream->metadata, "MATROSKA/TITLE", NULL, 0);
			if (!title || strcasecmp(title->value, "Cover (front)"))
				continue;
			in->cover_front = stream;
		}
	}

	if (!in->s.audio) {
		print_file_error(playlist, &f->a, "No audio streams found", NULL);
		return -1;
	}

	const AVCodec *codec;

	/* Find a decoder for the audio stream. */
	if (!(codec = avcodec_find_decoder(in->s.audio->codecpar->codec_id))) {
		print_file_error(playlist, &f->a, "Could not find decoder", NULL);
		return -1;
	}

	/* Allocate a new decoding context. */
	if (!(in->s.codec_ctx = avcodec_alloc_context3(codec))) {
		print_file_error(playlist, &f->a, "Could not allocate codec", NULL);
		return -1;
	}

	/* Initialize the stream parameters with demuxer information. */
	rc = avcodec_parameters_to_context(in->s.codec_ctx, in->s.format_ctx->streams[0]->codecpar);
	if (rc < 0) {
		print_file_averror(playlist, &f->a, "Could not initalize codec parameters", rc);
		return -1;
	}

	in->s.codec_ctx->time_base = in->s.audio->time_base;

	rc = avcodec_open2(in->s.codec_ctx, codec, NULL);
	if (rc < 0) {
		print_file_averror(playlist, &f->a, "Could not open codec", rc);
		return -1;
	}

	read_metadata(&cur_in);

	return 0;
}

static int
open_output(char const *format_ctx, char const *url, Output *out, Input const *in)
{
	const AVCodec *codec;
	enum AVCodecID codec_id = av_get_pcm_codec(in->s.codec_ctx->sample_fmt, -1);
	/* Find the encoder to be used by its name. */
	if (!(codec = avcodec_find_encoder(codec_id)))
		return -1;

	/* Configuration not changed. */
	if (out->s.codec_ctx &&
	    codec == out->s.codec_ctx->codec &&
	    out->s.codec_ctx->sample_rate == in->s.codec_ctx->sample_rate &&
	    out->s.codec_ctx->channels == in->s.codec_ctx->channels)
		return 0;

	close_output(out);

	int rc;

	rc = avformat_alloc_output_context2(&out->s.format_ctx, NULL, format_ctx, url);
	if (rc < 0)
		return -1;

	out->next_pts = 0;

#if 0
	if (!(AVFMT_NOFILE & out->s.format_ctx->flags)) {
		ret = avio_open(&out->s.format_ctx->pb, url, AVIO_FLAG_WRITE);
		if (ret < 0)
			return ret;
	}
#endif

	AVStream *stream;
	/* Create a new audio stream in the output file container. */
	if (!(stream = avformat_new_stream(out->s.format_ctx, NULL)))
		return -1;

	if (!(out->s.codec_ctx = avcodec_alloc_context3(codec)))
		return -1;

	/* Set the basic encoder parameters.
	 * The input file's sample rate is used to avoid a sample rate conversion. */
	out->s.codec_ctx->channels = in->s.codec_ctx->channels;
	out->s.codec_ctx->channel_layout = av_get_default_channel_layout(out->s.codec_ctx->channels);
	out->s.codec_ctx->sample_rate = in->s.codec_ctx->sample_rate;
	out->s.codec_ctx->sample_fmt = codec->sample_fmts[0];
	out->s.codec_ctx->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;

	if (out->s.format_ctx->oformat->flags & AVFMT_GLOBALHEADER)
		out->s.codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	if (/* Open the encoder for the audio stream to use it later. */
	    (rc = avcodec_open2(out->s.codec_ctx, codec, NULL)) < 0 ||
	    (rc = avcodec_parameters_from_context(stream->codecpar, out->s.codec_ctx)) < 0 ||
	    (rc = avformat_write_header(out->s.format_ctx, NULL)) < 0)
		return -1;

	out->s.audio = out->s.format_ctx->streams[0];

	if (!(out->fifo = av_audio_fifo_alloc(out->s.codec_ctx->sample_fmt,
			out->s.codec_ctx->channels,
			out->s.codec_ctx->time_base.den)))
		return -1;

	return 0;
}

/* FIXME: ( ... ) is fucked. Use [!][& |]() and implement correct stack. */
typedef struct {
	uint64_t mxs;
	uint8_t level; /* How deep we are inside of "("s. */
	unsigned or: 1,
	         neg: 1;
	unsigned lt: 1,
	         eq: 1,
	         gt: 1,
	         not: 1;
	union {
		regex_t reg;
		char str[64];
	};
} Clause;

static char const *
parse_number(char const *s, uint64_t *ret)
{
	while (*s && !('0' <= *s && *s <= '9'))
		++s;
	if (!*s)
		return NULL;

	uint64_t n = 0;
	do
		n = 10 * n + (*s++ - '0');
	while ('0' <= *s && *s <= '9');

	/* Units. */
	if ('m' == *s)
		n *= 60;

	*ret = n;
	return s;
}

static uint64_t
get_file_index(PlaylistFile pf)
{
	uint64_t ret = 0;

	Playlist const *parent = pf.p;
	AnyFile const *a = &pf.f->a;

	for (; parent; a = &parent->a, parent = parent->parent) {
		AnyFile const *child = parent->files;

		for_each_playlist(playlist, parent) {
			if (a <= &playlist->a)
				break;

			ret += 1 /* Self. */ + playlist->child_filter_count[0];
			child = (void *)((char *)playlist + get_file_size(F_PLAYLIST));
		}

		ret += (File *)a - (File *)child;
	}

	return ret;
}

static void
print_file(PlaylistFile pf, FILE *stream)
{
	File const *f = pf.f;
	char const *str;

	flockfile(stream);

#define M(name) (f->metadata[M_##name] && (str = f->a.url + f->metadata[M_##name]))

	if (!M(album_artist) && !M(artist) && !M(title)) {
		if (!(str = strrchr(f->a.url, '/')))
			str = f->a.url;
		else
			++str;

		int has_space = 0;
		size_t dots = 0;
		size_t dashes = 0;
		size_t lowlines = 0;
		for (char const *s = str; *s; ++s) {
			dots += '.' == *s;
			dashes += '-' == *s;
			lowlines += '_' == *s;
			has_space |= ' ' == *s;
		}
		if (has_space || !(dots | dashes | lowlines)) {
			fputs(str, stream);
		} else {
			size_t n = dots;
			char space = '.';

			if (n <= dashes)
				n = dashes, space = '-';

			if (n <= lowlines)
				n = lowlines, space = '_';

			for (char const *s = str; *s; ++s)
				fputc(space == *s ? ' ' : *s, stream);
		}
	} else {
#define PRINT_NUMBER(name) \
		if (!(M(name##_total) && \
		      !memcmp(str, "1", 2)) && \
		    M(name)) \
		{ \
			fputc('(', stream); \
			fputs(str, stream); \
			if (M(name##_total)) { \
				fputc('/', stream); \
				fputs(str, stream); \
			} \
			fputs(") ", stream); \
		}

#define PRINT_TITLE(params, title, version) \
		if (M(title)) { \
			fprintf(stream, "\e["params"m%s\e[m", str); \
			if (M(version)) \
				fprintf(stream, " (\e["params"m%s\e[m)", str); \
		} else { \
			fputs("ID", stream); \
		}

		if (M(date))
			fprintf(stream, "%-10s ", str);

		/* Artist 1;Artist 2 */
		if (M(album_artist)) {
			char const *d = str;
			int any = 0;

			for (char const *s = str; *s;) {
				char const *p = strchr(s, ';');
				if (!p)
					p = s + strlen(s);
				if (any)
					fputc(';', stream);
				any = 1;
				fprintf(stream, "\e[m%.*s\e[m", (int)(p - s), s);
				if (*(s = p))
					++s;
			}

			if (M(artist)) {
				size_t dn = strlen(d);
				for (char const *s = str; *s;) {
					char const *p = strchr(s, ';');
					size_t sn = p ? (size_t)(p - s) : strlen(s);
					char const *q = memmem(d, dn, s, sn);

					if (!q ||
					    ('\0' != q[-1] && ';' != q[-1]) ||
					    ('\0' != q[sn] && ';' != q[sn]))
					{
						if (any)
							fputc(';', stream);
						any = 1;
						fprintf(stream, "\e[m%.*s\e[m", (int)(p - s), s);
					}

					if (p)
						s = p + 1;
					else
						break;
				}
			}
		} else if (M(artist)) {
			fputs(str, stream);
		} else {
			fputs("ID", stream); \
		}
		fputs(" - ", stream);

		/* 01/01. [CATALOG] Album Title (Album Version) [LABEL] [BARCODE] */
		PRINT_NUMBER(disc);

		if (M(catalog))
			fprintf(stream, "[%s] ", str);

		PRINT_TITLE("", album, album_version);

		if (M(label))
			fprintf(stream, " [%s]", str);

		if (M(barcode))
			fprintf(stream, " [BARCODE %s]", str);
		fputs(" / ", stream);

		/* 01/22. Track Title (Track Version) (ft. Artist3;Artist4) [ISRC] {Genre 1;Genre2} */

		PRINT_NUMBER(track);
		PRINT_TITLE(";1", title, version);
		/* ;33;40 */

		if (M(featured_artist))
			fprintf(stream, " (ft. \e[m%s\e[m)", str);

		if (M(isrc))
			fprintf(stream, " [ISRC %s]", str);

		if (M(genre))
			fprintf(stream, " {%s}", str);
	}

	if (M(play_count))
		fprintf(stream, " \e[37mplays=%s\e[m", str);
	if (M(skip_count))
		fprintf(stream, " \e[37mskips=%s\e[m", str);

#undef M

	fputc('\n', stream);

	funlockfile(stream);
}

static char const *
get_metadata(Playlist const *playlist, File const *f, enum MetadataX m)
{
	if (m < (enum MetadataX)M_NB)
		return f->metadata[m] ? f->a.url + f->metadata[m] : NULL;
	else switch (m) {
	case MX_url:
		return f->a.url;

	case MX_name:
	{
		char const *p = strrchr(f->a.url, '/');
		return p ? p + 1 : f->a.url;
	}

	case MX_playlist:
		return playlist ? (
			playlist->name
				? playlist->name
				: playlist->a.url
		) : NULL;

	default:
		abort();
	}
}

typedef struct {
	struct {
		uint64_t nb_files;
		uint64_t nb_playlists;
		uint64_t duration;
		uint64_t nb_unscanned;
		uint64_t nb_untagged;
	} total, filtered;
} Stat;

static int
has_metadata(File const *f)
{
	return
		f->metadata[M_artist] &&
		f->metadata[M_title];
}

static int
collect_stat(AnyFile *a, Stat *s)
{
	if (F_FILE < a->type) {
		Playlist *playlist = (void *)a;

		s->total.nb_playlists += &master != playlist;

		int any = 0;
		for_each_file()
			any |= collect_stat(a, s);

		s->filtered.nb_playlists += any && &master != playlist;
		return any;
	}

	File *f = (void *)a;

	uint64_t duration = f->metadata[M_duration] ? strtoull(a->url + f->metadata[M_duration], NULL, 10) : 0;

#define COLLECT(type) \
	s->type.duration += duration; \
	s->type.nb_unscanned += !f->metadata[M_duration]; \
	s->type.nb_untagged += f->metadata[M_duration] && !has_metadata(f);

	COLLECT(total);

	if (!((UINT32_C(1) << cur_filter[1]) & a->filter_mask))
		return 0;

	COLLECT(filtered);

#undef COLLECT

	return 1;
}

static void
calc_stat(Stat *s)
{
	*s = (Stat){
		.total = {
			.nb_files = master.child_filter_count[cur_filter[1]],
		},
		.filtered = {
			.nb_files = master.child_filter_count[0],
		},
	};
	collect_stat(&master.a, s);
}

static uint64_t
match_file(Playlist *parent, AnyFile *a, uint8_t filter_index, Clause const *clauses, size_t nb_clauses)
{
	if (F_FILE < a->type) {
		uint64_t count = 0;
		Playlist *playlist = (void *)a;

		for_each_file()
			count += match_file(playlist, a, filter_index, clauses, nb_clauses);

		return (playlist->child_filter_count[filter_index] = count);
	}

	File *f = (void *)a;

	uint8_t stack[CLAUSE_LEVEL_MAX];
	uint8_t level = 0;
	stack[level] = 1;

	if (!nb_clauses)
		stack[level] = 1;
	else for (size_t i = 0; i < nb_clauses; ++i) {
		Clause const *clause = &clauses[i];
		if (level < clause->level)
		stack[clause->level] = stack[level];
		level = clause->level;

		/* Expression does not affect result. */
		if (stack[level] == clause->or)
			continue;

		for (uint64_t mxs = clause->mxs; mxs;) {
			enum MetadataX m = __builtin_ctz(mxs);
			mxs ^= UINT64_C(1) << m;

			char const *value = get_metadata(parent, f, m);

			/* Fallback to the URL if metadata is missing for this
			 * file. This way user can avoid nasty queries in a new
			 * playlist. */
			if (!value &&
			    ((enum MetadataX)M_artist == m ||
			     (enum MetadataX)M_title == m) &&
			    !has_metadata(f))
				value = f->a.url;
			else if (!value) {
				if (!clause->not)
					goto no_match;
				else
					goto matched;
			}

			if (clause->lt | clause->gt) {
				char const *s = clause->str;
				char const *v = value;

				for (;;) {
					uint64_t sn, vn;
					if (!(s = parse_number(s, &sn))) {
						if (clause->not == clause->eq)
							/* 2020-01-03 /y<2020-01 */
							/* 2020-01-03 /y>2020-01 */
							goto no_match;
						else
							/* 2020-01-03 /y<=2020-01 */
							/* 2020-01-03 /y>=2020-01 */
							/* 2020-01-03 /y=2020-01 */
							goto matched;
					}

					if (!(v = parse_number(v, &vn)) ||
					    /* Decide on first difference. */
					    (vn != sn &&
					     (clause->lt != (vn < sn) ||
					      clause->gt != (vn > sn))))
					{
						if (!clause->not)
							goto no_match;
						else
							goto matched;
					}
				}
			} else {
				if (clause->not != (REG_NOMATCH == regexec(&clause->reg, value, 0, NULL, 0)))
					goto no_match;
				else
					goto matched;
			}

		no_match:;
			/* Continue with an alternative metadata. */
		}

		/* Note that result can be written directly because clause->or
		 * does not affect end result. */
		if ((stack[level] = 0)) {
		matched:;
			stack[level] = 1;
		}

		/* Continue with next clause. */
	}

	if (!stack[0]) {
		f->a.filter_mask &= ~(UINT32_C(1) << filter_index);
		return 0;
	}

	f->a.filter_mask |= UINT32_C(1) << filter_index;

	return 1;
}

#define POS_RND INT64_MIN

/* TODO: In playlists named ".queue", current file is always destroyed after
 * seeking. */
/* TODO: Append current entry to playlist named ".history". */
static PlaylistFile
seek_playlist(Playlist const *playlist, PlaylistFile const *cur, int64_t pos, int whence)
{
	uint64_t max = playlist->child_filter_count[cur_filter[live]];
	if (!max)
		return (PlaylistFile){};

	if (SEEK_END == whence && POS_RND != pos) {
		pos += max - 1;
		whence = SEEK_SET;
	}

	int dir = 1;
	if (POS_RND == pos) {
		/* Tweak random a bit by making sure that we do not play twice the same file. */
		if (max <= 1)
			pos = 0;
		else
			pos = rndn(&rnd, max - 1) + 1;
		whence = SEEK_CUR;
	} else if (0 <= pos)
		pos %= max;
	else {
		pos = -pos % max;
		dir = -1;
	}


	AnyFile const *a;
	if (SEEK_CUR == whence) {
		if (!cur)
			cur = &cur_in.pf;

		playlist = cur->p;
		a = cur->f ? &cur->f->a : &master.a;
	} else {
		a = &playlist->a;
		playlist = playlist->parent;
	}

	for (;;) {
		if (F_FILE < a->type) {
			Playlist const *p = (void *)a;
			uint64_t n;

			n = p->child_filter_count[cur_filter[live]];
			if (n < (uint64_t)pos || !p->files_size) {
				/* Step over. */
				pos -= n;
			} else {
				/* Step in. */
				playlist = (void *)a;
				a = (void *)((char *)p->files + (0 <= dir ? 0 : p->files_size - get_file_size(p->last_child_type)));
				continue;
			}
		}

		if (a->type <= F_FILE &&
		    ((UINT32_C(1) << cur_filter[live]) & a->filter_mask))
		{
			if (!pos)
				break;
			--pos;
		}

		/* Step out. */
		while (playlist &&
		       ((dir < 0 && playlist->files == a) ||
		        (0 <= dir && (void *)((char *)playlist->files + playlist->files_size - get_file_size(playlist->last_child_type)) == a)))
		{
			a = &playlist->a;
			playlist = ((Playlist *)a)->parent;
		}

		/* Start again from the other side. */
		if (!playlist) {
			playlist = (void *)a;
			a = (void *)((char *)playlist->files + (0 <= dir ? 0 : playlist->files_size - get_file_size(playlist->last_child_type)));
		} else if (0 <= dir) {
			PTR_INC(a, get_file_size(a->type));
		} else {
			PTR_INC(a, -get_file_size(a->prev_type));
		}
	}

	assert(a->type <= F_FILE);
	assert(F_FILE < playlist->a.type);
	return (PlaylistFile){ (Playlist *)playlist, (File *)a, };
}

/**
 * @param s "(" [LETTER[<][>][!][=]EXPR]... " | " ")"
 */
static void
search_file(Playlist *parent, Playlist *playlist, uint8_t filter_index, char const *s)
{
	Clause clauses[M_NB], *clause = clauses;
	char buf[1 << 12];

	char const *orig = s;
	char const *error_msg = NULL;
	char const *p;

	uint8_t level = 0;

	struct timespec start;
	xassert(!clock_gettime(CLOCK_MONOTONIC, &start));

append:;
	uint8_t unkeyed = 0;
	int has_playlist_clause = 0;
	int or = 0;
	while (*s) {
		switch (*s) {
		case ' ':
		case '\t':
			++s;
			continue;

		case '(':
			if (CLAUSE_LEVEL_MAX == level + 1) {
				p = NULL;
				error_msg = "Maximum nesting depth reached";
				goto cleanup;
			}
			++s;
			++level;
			or = 0;
			continue;

		case ')':
			if (!level) {
				p = NULL;
				error_msg = "Unmatched )";
				goto cleanup;
			}
			++s;
			--level;
			or = 0;
			continue;

		case '|':
			++s;
			or = 1;
			continue;

		case '&':
			++s;
			or = 0;
			continue;
		}

		clause->or = or;
		clause->level = level;
		clause->mxs = 0;
		while (('a' <= *s && *s <= 'z') ||
		       ('A' <= *s && *s <= 'Z'))
		{
			if (!(p = memchr(METADATA_LETTERS, *s, sizeof METADATA_LETTERS))) {
				error_msg = "Unknown field specifier";
				goto cleanup;
			}
			++s;

			enum MetadataX m = p - METADATA_LETTERS;
			clause->mxs |= UINT64_C(1) << m;

			has_playlist_clause |= MX_playlist == m;
		}
		if (!clause->mxs) {
#define B(m) (UINT64_C(1) << M_##m)
			switch (unkeyed) {
			case 0:
				clause->mxs =
					B(album) |
					B(album_version) |
					B(title) |
					B(version);
				++unkeyed;
				break;

			case 1:
				clause->mxs =
					B(album_artist) |
					B(album_featured_artist) |
					B(artist) |
					B(featured_artist) |
					B(remixer);
				break;
			}
#undef B
		}


		s += (clause->lt  = '<' == *s);
		s += (clause->gt  = '>' == *s);
		s += (clause->not = '!' == *s);
		s += (clause->eq  = '=' == *s);

		if ((clause->lt | clause->gt) && clause->not)
			clause->lt ^= 1,
			clause->gt ^= 1,
			clause->eq ^= 1;
		else if (!(clause->lt | clause->gt | clause->eq))
			clause->eq = 1;

		size_t buf_size = 0;
		p = s;
		char right = '"' == *p || '\'' == *p ? *p++ : '\0';

		for (; '\\' == *p ? *++p : *p && (right ? right != *p : ' ' != *p && ')' != *p); ++p) {
			unsigned special_space = 0;
			if (' ' == *p) {
				unsigned escaped = 0;
				for (size_t i = buf_size; 0 < i && '\\' == buf[--i];)
					escaped ^= 1;
				special_space = !escaped;
			}

			if (special_space) {
				if (sizeof buf - 1 /* NUL */ - 6 < buf_size)
					goto fail_too_long;
				memcpy(buf + buf_size, "[._ -]+", 6);
				buf_size += 6;
			} else {
				if (sizeof buf - 1 /* NUL */ - 1 < buf_size) {
				fail_too_long:
					error_msg = "Too long";
					goto cleanup;
				}
				buf[buf_size++] = *p;
			}
		}

		/* No value. */
		if (p == s) {
			File const *f = cur_in.pf.f;
			if (!f) {
				error_msg = "No file is playing";
				goto cleanup;
			}

			for (uint64_t mxs = clause->mxs; mxs;) {
				enum MetadataX m = __builtin_ctz(mxs);
				mxs ^= UINT64_C(1) << m;

				p = f->metadata[m] ? f->a.url + f->metadata[m] : "";
				while (*p && ';' != *p) {
					switch (*p) {
					case '(': case ')':
					case '{': case '}':
					case '[': case ']':
					case '?': case '*': case '+':
					case '.':
					case '|':
					case '^': case '$':
					case '\\':
						if (sizeof buf - 1 /* NUL */ - 2 < buf_size) {
							p = NULL;
							goto fail_too_long;
						}
						buf[buf_size++] = '\\';
						break;

					default:
						if (sizeof buf - 1 /* NUL */ - 1 < buf_size) {
							p = NULL;
							goto fail_too_long;
						}
						break;
					}

					buf[buf_size++] = *p++;
				}
			}
		}

		buf[buf_size] = '\0';

		if (clause->lt | clause->gt) {
			if (sizeof clause->str < buf_size)
				goto fail_too_long;

			memcpy(clause->str, buf, buf_size);
		} else {
			int rc = regcomp(&clause->reg, buf, REG_EXTENDED | REG_ICASE | REG_NOSUB);
			if (rc) {
				regerror(rc, &clause->reg, buf, sizeof buf);
				error_msg = buf;
				goto cleanup;
			}
		}
		s = p;

		if (*s && right)
			++s;

		++clause;
		or = 0;
	}
	/* Let it be an error since (x=y) is not "( x=y )" but "( x='y)'". */
	if (level) {
		p = NULL;
		error_msg = "Unclosed (";
		goto cleanup;
	}

	if (!has_playlist_clause) {
		s = "p=^[^.]";
		goto append;
	}

	fprintf(tty, "Searching for \e[1m%s\e[m..."LF, orig);

	match_file(parent, &playlist->a, filter_index, clauses, clause - clauses);

	struct timespec finish;
	xassert(!clock_gettime(CLOCK_MONOTONIC, &finish));

	double elapsed = ((finish.tv_sec - start.tv_sec) * NS_PER_SEC + (finish.tv_nsec - start.tv_nsec)) / (double)NS_PER_SEC;

	fprintf(tty, "Search finished in %.3f s: ", elapsed);
	uint64_t total = master.child_filter_count[filter_index];
	if (total)
		fprintf(tty, "\e[1;32m%"PRIu64, total);
	else
		fputs("No", tty);
	fputs(" files matched\e[m\n", tty);

cleanup:
	if (error_msg) {
		fprintf(tty, "\e[1;31mError: %s\e[m"LF, error_msg);

		fprintf(tty, "%s\n", orig);
		fprintf(tty, "\e[%uG\e[1;31m^", (unsigned)(s - orig) + 1);
		while (++s < p)
			fputc('~', tty);
		fputs("\e[m\n", tty);
	}

	while (clauses < clause--)
		if (!(clause->lt | clause->gt))
			regfree(&clause->reg);
}

static int
init_resampler(SwrContext **resampler, AVCodecContext *in_codec, AVCodecContext *out_codec)
{
	*resampler = swr_alloc_set_opts(*resampler,
			av_get_default_channel_layout(out_codec->channels),
			out_codec->sample_fmt,
			out_codec->sample_rate,
			av_get_default_channel_layout(in_codec->channels),
			in_codec->sample_fmt,
			in_codec->sample_rate,
			0, NULL);
	if (!*resampler)
		return -1;

	/* FIXME: Why is it needed? */
	assert(out_codec->sample_rate == in_codec->sample_rate);

	/* Open the resampler with the specified parameters. */
	int rc = swr_init(*resampler);
	if (rc < 0) {
		swr_free(resampler);
		return -1;
	}
	return 0;
}

static void
print_stream(Stream const *s, int output, FILE *stream)
{
	char const *format_name = output
		? s->format_ctx->oformat->name
		: s->format_ctx->iformat->name;
	char const *codec_name = s->codec_ctx->codec->name;
	fprintf(stream, "%s(%s)", format_name, codec_name);

	if (!output && AV_NOPTS_VALUE != s->audio->duration) {
		int64_t duration = av_rescale_rnd(
				s->audio->duration,
				s->audio->time_base.num,
				s->audio->time_base.den,
				AV_ROUND_DOWN);
		fprintf(stream, ", %3"PRId64":%02hu", duration / 60, (unsigned char)(duration % 60));
	}

	if (44100 != s->codec_ctx->sample_rate)
		fprintf(stream, ", %d Hz", s->codec_ctx->sample_rate);

	if (AV_CH_LAYOUT_STEREO != s->codec_ctx->channel_layout) {
		fputs(", ", stream);
		char buf[128];
		av_get_channel_layout_string(buf, sizeof buf,
				s->codec_ctx->channels, s->codec_ctx->channel_layout);
		fputs(buf, stream);
	}

	int64_t bit_rate = s->codec_ctx->bit_rate;
	if (!bit_rate)
		bit_rate = s->format_ctx->bit_rate;
	if (bit_rate)
		fprintf(stream, ", %"PRId64" kb/s", bit_rate / 1000);
}

static void
print_output(Output const *out, FILE *stream)
{
	print_stream(&out->s, 1, stream);
}

static void
print_input(Input const *in, FILE *stream)
{
	print_stream(&in->s, 0, stream);
	if (in->cover_front)
		fprintf(stream, "; cover_front(%s), %dx%d",
				avcodec_get_name(in->cover_front->codecpar->codec_id),
				in->cover_front->codecpar->width,
				in->cover_front->codecpar->height);
}

static int
receive_frame(AVFrame *frame, Stream *s)
{
	int rc;
	AVPacket *in_pkt;

	if (!(in_pkt = av_packet_alloc()))
		return AVERROR(ENOMEM);

	/* Read packet from input. */
	for (;;) {
		rc = av_read_frame(s->format_ctx, in_pkt);
		if (rc < 0) {
			if (AVERROR(EAGAIN) == rc)
				continue;
			else if (AVERROR_EOF != rc)
				av_log(s->format_ctx, AV_LOG_ERROR, "Could not read frame: %s\n",
						av_err2str(rc));
			return rc;
		}

		if (s->audio->index == in_pkt->stream_index)
			break;

		av_packet_unref(in_pkt);
	}

	if (/* Send read packet for decoding. */
	    ((rc = avcodec_send_packet(s->codec_ctx, in_pkt)) < 0) ||
	    /* Receive decoded frame. */
	    ((rc = avcodec_receive_frame(s->codec_ctx, frame)) < 0 &&
	     (AVERROR(EAGAIN) != rc)))
		av_log(s->format_ctx, AV_LOG_ERROR, "Could not decode frame: %s\n",
				av_err2str(rc));

	av_packet_free(&in_pkt);

	return rc;
}

static void
print_progress(int force)
{
	if (!tty)
		return;

	static int64_t old_clock = 0, old_total = 0;

	int64_t clock = cur_out.s.codec_ctx
		? (AV_NOPTS_VALUE != master_pts ? master_pts : 0) / cur_out.s.codec_ctx->sample_rate
		: 0;

	int percent_known = 0;
	int64_t total;
	if (cur_in.s.format_ctx) {
		total = cur_in.s.format_ctx->duration;
		if (AV_NOPTS_VALUE != total) {
			total /= AV_TIME_BASE;
			percent_known = 1;
		} else {
			total = cur_out.s.codec_ctx
				? ((AV_NOPTS_VALUE != master_pts ? master_pts : 0) + av_audio_fifo_size(cur_out.fifo)) / cur_out.s.codec_ctx->sample_rate
				: 0;
		}
	} else {
		total = 0;
	}

	if (!force && clock == old_clock && total == old_total)
		return;
	old_clock = clock;
	old_total = total;

	fprintf(tty, "%"PRId64"%c%c%c ",
			cur_number,
			has_number ? '?' : '\0',
			next_cmd,
			paused ? '.' : '>');

	fprintf(tty, "%3"PRId64":%02u / %3"PRId64":%02u (%3u%%)",
			clock / 60, (unsigned)(clock % 60),
			total / 60, (unsigned)(total % 60),
			percent_known && total ? (unsigned)(clock * 100 / total) : 0);

	if (debug)
		fprintf(tty, " (buffer=%7llu ms)",
				av_audio_fifo_size(cur_out.fifo) * 1000ULL / cur_out.s.codec_ctx->sample_rate);
	fputs(CR, tty);
}

static int
decode_frame(Input *in, Output *out)
{
	uint8_t **out_samples = NULL;
	int rc = 0;

	if (!in->s.format_ctx)
		return AVERROR_EOF;

	AVFrame *in_frame;
	if (!(in_frame = av_frame_alloc())) {
		rc = AVERROR(ENOMEM);
		goto out;
	}

	rc = receive_frame(in_frame, &in->s);
	if (rc < 0)
		goto out;

	int nb_out_samples = in_frame->nb_samples;
	rc = av_samples_alloc_array_and_samples(&out_samples, NULL, out->s.codec_ctx->channels,
			nb_out_samples,
			out->s.codec_ctx->sample_fmt, 0);
	if (rc < 0) {
		av_log(NULL, AV_LOG_ERROR,
				"Could not allocate converted input samples (error '%s')\n",
				av_err2str(rc));
		goto out;
	}

	xassert(nb_out_samples <= swr_get_out_samples(in->resampler, in_frame->nb_samples));

	rc = swr_convert(in->resampler,
			out_samples, nb_out_samples,
			(void *)in_frame->extended_data, in_frame->nb_samples);
	if (rc < 0) {
		av_log(NULL, AV_LOG_ERROR,
				"Could not convert input samples: %s\n",
				av_err2str(rc));
		goto out;
	}

	xassert(!pthread_mutex_lock(&out->fifo_mutex));

	/* Synchronize pts. */
	if (!av_audio_fifo_size(out->fifo)) {
		cur_out.cur_frame = av_rescale_q_rnd(in_frame->pts - (AV_NOPTS_VALUE != in->s.audio->start_time ? in->s.audio->start_time : 0),
				in->s.codec_ctx->time_base,
				(AVRational){ 1, out->s.codec_ctx->sample_rate },
				AV_ROUND_DOWN);
	}

	/* Store the new samples in the FIFO buffer. */
	rc = av_audio_fifo_write(out->fifo, (void *)out_samples, in_frame->nb_samples);
	if (rc < 0) {
		av_log(NULL, AV_LOG_ERROR,
				"Could not buffer converted samples: %s\n",
				av_err2str(rc));
		goto out_unlock;
	}

	if (AV_NOPTS_VALUE == cur_in.s.format_ctx->duration && tty) {
		print_progress(0);
		fflush(tty);
	}

	xassert(!pthread_cond_signal(&out->fifo_cond));

	out->cache_counter += in_frame->nb_samples;
	/* Step cache_level if we are playing continously for a while. */
	if (((out->cache_counter / out->s.codec_ctx->sample_rate) >> out->cache_level)) {
		out->cache_counter = 0;
		if (CACHE_LEVEL_MAX < ++out->cache_level)
			out->cache_level = CACHE_LEVEL_MAX;
	}

out_unlock:
	xassert(!pthread_mutex_unlock(&out->fifo_mutex));

out:
	if (out_samples) {
		av_free(*out_samples);
		av_free(out_samples);
	}
	av_frame_free(&in_frame);

	return rc;
}

static int
send_frame(Output *out, AVFrame *in_frame, AVPacket *out_pkt)
{
	int rc;

	/* Send a frame to encode. */
	rc = avcodec_send_frame(out->s.codec_ctx, in_frame);
	if (rc < 0)
		av_log(out->s.format_ctx, AV_LOG_ERROR,
				"Could not encode frame: %s\n",
				av_err2str(rc));

	while (0 <= rc) {
		/* Receive an encoded packet. */
		rc = avcodec_receive_packet(out->s.codec_ctx, out_pkt);
		if (rc < 0) {
			/* Encoder asks for more data. We will give it later. */
			if (AVERROR(EAGAIN) == rc) {
				rc = 0;
				break;
			}

			break;
		}

		master_pts = out_pkt->pts;

		out_pkt->pts = out->next_pts;
		out_pkt->dts = out_pkt->pts;
		out->next_pts += out_pkt->duration;

		rc = av_write_frame(out->s.format_ctx, out_pkt);
		if (rc < 0) {
			if (AVERROR(EAGAIN) == rc)
				rc = AVERROR_BUG;
			av_log(out->s.format_ctx, AV_LOG_ERROR,
					"Could not write encoded frame: %s\n",
					av_err2str(rc));
		}
		av_packet_unref(out_pkt);
	}

	return rc;
}

static void
seek_player(int64_t ts, int whence)
{
	int64_t target_pts;

	xassert(!pthread_rwlock_wrlock(&cur_rwlock));

	Input *in = &cur_in;
	Output *out = &cur_out;

	xassert(!pthread_mutex_lock(&out->fifo_mutex));

	if (!in->s.format_ctx || !out->s.codec_ctx)
		goto out;

	sought = 1;

	int64_t cur_pts = av_rescale_q_rnd(master_pts,
			(AVRational){ 1, out->s.codec_ctx->sample_rate },
			in->s.audio->time_base,
			AV_ROUND_DOWN);

	ts = av_rescale_rnd(ts,
			in->s.audio->time_base.den,
			in->s.audio->time_base.num,
			AV_ROUND_DOWN);

	switch (whence) {
	case SEEK_SET:
		target_pts = ts;
		break;

	case SEEK_CUR:
		if (AV_NOPTS_VALUE == master_pts)
			goto out;

		target_pts = cur_pts + ts;
		break;

	case SEEK_END:
		if (AV_NOPTS_VALUE != in->s.format_ctx->duration)
			abort();
		target_pts = in->s.format_ctx->duration + ts;
		break;

	default:
		abort();
	}

	if (target_pts < 0)
		target_pts = 0;

	int64_t first_pts = in->s.format_ctx->start_time;
	if (AV_NOPTS_VALUE == first_pts)
		first_pts = 0;

	target_pts += first_pts;

	/* avformat_flush(out->s.format_ctx); */

	avcodec_flush_buffers(in->s.codec_ctx);
	avcodec_flush_buffers(out->s.codec_ctx);

	if (av_write_frame(out->s.format_ctx, NULL) < 0)
		av_log(out->s.format_ctx, AV_LOG_ERROR, "Could not flush encoder\n");

	uint64_t cur_frame = cur_out.cur_frame;
	uint64_t target_frame = av_rescale_q_rnd(target_pts,
			in->s.audio->time_base,
			(AVRational){ 1, out->s.codec_ctx->sample_rate },
			AV_ROUND_DOWN);
	if (cur_frame < target_frame && target_frame <= cur_frame + av_audio_fifo_size(out->fifo)) {
		av_audio_fifo_drain(out->fifo, target_frame - cur_frame);
		cur_out.cur_frame += target_frame - cur_frame;
	} else {
		if (avformat_seek_file(in->s.format_ctx, in->s.audio->index, 0, target_pts, target_pts, 0) < 0)
			av_log(in->s.format_ctx, AV_LOG_ERROR, "Could not seek\n");
		av_audio_fifo_reset(out->fifo);

		/* Not to the beginning of the stream. */
		if (target_pts) {
			/* Sought to a distant position. */
			uint64_t dist_sec = 2 * av_rescale_rnd(labs(cur_pts - target_pts),
					in->s.audio->time_base.num,
					in->s.audio->time_base.den,
					AV_ROUND_UP);
			while (0 < out->cache_level &&
			       dist_sec < (UINT64_C(1) << out->cache_level))
				--out->cache_level;
		}
	}
	out->cache_counter = 0;

	out->fifo_stopped = 0;

	xassert(!pthread_cond_signal(&out->fifo_cond));

out:
	xassert(!pthread_mutex_unlock(&out->fifo_mutex));
	xassert(!pthread_rwlock_unlock(&cur_rwlock));
}

static void
_pthread_mutex_unlock(void *mutex)
{
	xassert(!pthread_mutex_unlock(mutex));
}

static void
print_now_playing(void)
{
	char buf[20];
	strftime(buf, sizeof buf, "\e[1;33m%R> \e[m", localtime(&(time_t){ time(NULL) }));
	fputs(buf, tty);
}

static void *
source_worker(void *arg)
{
	(void)arg;

#if HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), "source");
#endif

	Input *in = &cur_in;
	Output *out = &cur_out;

	for (;;) {
		xassert(!pthread_mutex_lock(&out->fifo_mutex));
		pthread_cleanup_push(_pthread_mutex_unlock, &out->fifo_mutex);
		/* Allowed to cache more. */
		while (!out->s.codec_ctx ||
		       (out->s.codec_ctx->sample_rate << out->cache_level) <= av_audio_fifo_size(out->fifo))
			xassert(!pthread_cond_wait(&out->fifo_cond, &out->fifo_mutex));
		pthread_cleanup_pop(1);

		xassert(!pthread_rwlock_rdlock(&cur_rwlock));
		xassert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
		int rc = decode_frame(in, out);
		if (0 <= rc && (AVSTREAM_EVENT_FLAG_METADATA_UPDATED & in->s.format_ctx->event_flags) && tty) {
			in->s.format_ctx->event_flags &= ~AVSTREAM_EVENT_FLAG_METADATA_UPDATED;

			AVDictionaryEntry const *t = av_dict_get(in->s.format_ctx->metadata, "StreamTitle", NULL, 0);
			if (t) {
				print_now_playing();
				fprintf(tty, "[ICY] %s"LF, t->value);
				print_progress(1);
			}
		}
		xassert(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL));
		pthread_testcancel();
		if (rc < 0 && AVERROR(EAGAIN) != rc) {
			xassert(!pthread_mutex_lock(&out->fifo_mutex));
			pthread_cleanup_push(_pthread_mutex_unlock, &out->fifo_mutex);
			/* Important to keep locking player (in/out formats) while
			 * checking error codes, so we known that they still valid at
			 * this point and reflect the reality. */
			xassert(!pthread_rwlock_unlock(&cur_rwlock));

			/* Wait FIFO to be drained. */
			while (0 < av_audio_fifo_size(out->fifo)) {
				xassert(!pthread_cond_wait(&out->fifo_cond, &out->fifo_mutex));
				/*
				 * We may have seeked since than. FIFO will be empty and we
				 * check everything again. This still works if FIFO is not
				 * emptied by a seek, since:
				 * - If we seek backward FIFO is emptied. (At least
				 *   existing part must be temporary dropped.)
				 * - Seeking forward just drops frames at the start.
				 */
				rc = AVERROR(EAGAIN);
			}
			if (AVERROR(EAGAIN) != rc) {
				if (!out->fifo_stopped) {
					out->fifo_stopped = 1;
					write(control[W], (char const[]){ CONTROL('J') }, 1);
				}

				/* Suspend decoding. */
				xassert(!pthread_cond_wait(&out->fifo_cond, &out->fifo_mutex));
			}
			pthread_cleanup_pop(1);
		} else {
			xassert(!pthread_rwlock_unlock(&cur_rwlock));
		}
	}

	return NULL;
}

static void *
sink_worker(void *arg)
{
	(void)arg;

#if HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), "sink");
#endif

	Output *out = &cur_out;

	AVPacket *out_pkt;
	if (!(out_pkt = av_packet_alloc())) {
		av_log(NULL, AV_LOG_ERROR, "Could not allocate packet\n");
		return NULL;
	}

	pthread_cleanup_push((void(*)(void *))av_packet_free, &out_pkt);

	for (;;) {
		xassert(!pthread_rwlock_rdlock(&cur_rwlock));
		xassert(!pthread_mutex_lock(&out->fifo_mutex));

		int nb_frames = out->fifo ? av_audio_fifo_size(out->fifo) : 0;
		/* Request more samples to be decoded when at least half of the
		 * allowed buffer is empty. Using this method we can survive at most
		 * 2**cache_level / 2 seconds of demux delay without hurting audio
		 * playback. */
		if (out->s.codec_ctx && nb_frames <= (out->s.codec_ctx->sample_rate << out->cache_level) / 2)
			pthread_cond_signal(&out->fifo_cond);

		nb_frames = out->s.codec_ctx ? FFMIN(nb_frames, out->s.codec_ctx->sample_rate / 8) : 0;
		if (nb_frames <= 0 || paused) {
			xassert(!pthread_rwlock_unlock(&cur_rwlock));

			pthread_cleanup_push(_pthread_mutex_unlock, &out->fifo_mutex);
			xassert(!pthread_cond_wait(&out->fifo_cond, &out->fifo_mutex));
			pthread_cleanup_pop(1);
			continue;
		}

		xassert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));

		/* Hmm. For some reason allocating this frame once increases
		 * CPU usage by 2-3 times. */
		AVFrame *out_frame;
		if (!(out_frame = av_frame_alloc())) {
			av_log(NULL, AV_LOG_ERROR, "Could not allocate memory for frame\n");
		emergency:
			xassert(!pthread_mutex_unlock(&out->fifo_mutex));
			xassert(!pthread_rwlock_unlock(&cur_rwlock));
			continue;
		}

		out_frame->nb_samples     = nb_frames;
		out_frame->channel_layout = out->s.codec_ctx->channel_layout;
		out_frame->format         = out->s.codec_ctx->sample_fmt;
		out_frame->sample_rate    = out->s.codec_ctx->sample_rate;
		out_frame->pts            = cur_out.cur_frame;

		int rc;

		rc = av_frame_get_buffer(out_frame, 0);
		if (rc < 0) {
			av_frame_free(&out_frame);
			av_log(out->s.format_ctx, AV_LOG_ERROR,
					"Could not allocate frame: %s\n",
					av_err2str(rc));
			goto emergency;
		}

		rc = av_audio_fifo_read(out->fifo, (void **)out_frame->data, out_frame->nb_samples);
		if (0 <= rc)
			out->cur_frame += rc;
		assert(out_frame->nb_samples <= rc);

		xassert(!pthread_mutex_unlock(&out->fifo_mutex));

		if (0 <= rc) {
			/* Potentially others but ALSA sucks, by not being
			 * pthread_cancel() safe: When we try to close
			 * format_ctx, a mutex lock hangs inside
			 * snd_pcm_drain(). */
			rc = send_frame(out, out_frame, out_pkt);
		}

		av_frame_free(&out_frame);

		if (rc < 0)
			av_log(out->s.format_ctx, AV_LOG_ERROR,
					"Could not write samples: %s\n",
					av_err2str(rc));

		print_progress(0);

		xassert(!pthread_rwlock_unlock(&cur_rwlock));

		xassert(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL));
		pthread_testcancel();

		if (tty)
			fflush(tty);
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static void
save_master(void)
{
	save_playlist(&master);
}

static void
close_player(void)
{
	close_input(&cur_in);
	close_output(&cur_out);
}

static void
do_cleanup(void)
{
	if (threads_inited) {
		xassert(!pthread_cancel(source_thread));
		fputs("Waiting for producer thread to exit..."CR, tty);
		fflush(tty);
		xassert(!pthread_join(source_thread, NULL));

		fputs("Waiting for consumer thread to exit..."CR, tty);
		fflush(tty);
		xassert(!pthread_cancel(sink_thread));
		xassert(!pthread_join(sink_thread, NULL));
	}

	fputs("Destroying locks..."CR, tty);
	fflush(tty);
	xassert(!pthread_mutex_destroy(&cur_out.fifo_mutex));
	xassert(!pthread_cond_destroy(&cur_out.fifo_cond));
	xassert(!pthread_rwlock_destroy(&cur_rwlock));

	save_master();

	fputs("Releasing resources..."CR, tty);
	fflush(tty);
	cleanup_file(&master.a);

	close_player();
	swr_free(&cur_in.resampler);

	fputs(CR, tty);
	fclose(tty);
}

static void
restore_tty(void)
{
	tcsetattr(fileno(tty), TCSAFLUSH, &saved_termios);
}

static void
save_tty(void)
{
	tcgetattr(fileno(tty), &saved_termios);
	atexit(restore_tty);
}

static void
setup_tty(void)
{
	struct termios raw = saved_termios;
	raw.c_lflag &= ~(ECHO | ICANON);
	raw.c_lflag |= ISIG; /* Enable ^Z, ^C... */
	tcsetattr(fileno(tty), TCSAFLUSH, &raw);
}

static void
print_format(FILE *stream)
{
	flockfile(stream);
	print_input(&cur_in, stream);
	fputs(" -> ", stream);
	print_output(&cur_out, stream);
	fputs(LF, stream);
	funlockfile(stream);
}

static void
print_around(PlaylistFile pf)
{
	int rows = (term_height - 1) * 3 / 8;
	int bottom = -(rows * 3 / 8), top = bottom + rows;
	PlaylistFile first = seek_playlist(&master, NULL, 0, SEEK_SET);
	PlaylistFile last = seek_playlist(&master, NULL, 0, SEEK_END);

	int64_t offset = 0;
	for (; bottom < offset && pf.f != first.f; --offset)
		pf = seek_playlist(&master, &pf, -1, SEEK_CUR);

	fprintf(tty, "\e[K\e[?7l");
	for (;;) {
		fprintf(tty, "\e[;%dm%6"PRIu64"\e[m ",
				offset ? 0 : 7,
				offset ? labs(offset) : get_file_index(pf));

		print_file(pf, tty);
		if (top <= ++offset || pf.f == last.f)
			break;
		pf = seek_playlist(&master, &pf, 1, SEEK_CUR);
	}
	fprintf(tty, "\e[?7h");
}

static void
increment_xattr(Input *in, char const *xname, enum Metadata xm)
{
	if (!writable)
		return;

	File *f = in->pf.f;

	char *str = f->metadata[xm]
		? f->a.url + f->metadata[xm]
		: NULL;
	int oldn = str ? strlen(str) + 1 /* NUL */ : 0;
	uint64_t current = str ? strtoull(str, NULL, 10) : 0;

	++current;

	char buf[22];
	int n = sprintf(buf, "%"PRIu64, current);

	if (fsetxattr(in->fd, xname, buf, n, 0) < 0) {
	fail:
		print_file_strerror(in->pf.p, &f->a, "Could not write extended attributes");
		return;
	}
	n += 1 /* NUL */;

	if (oldn < n) {
		size_t size = 0;
		for (enum Metadata m = 0; m < M_NB; ++m)
			if (size < f->metadata[m])
				size = f->metadata[m];
		size += strlen(f->a.url + size) + 1 /* NUL */;

		void *p = realloc(f->a.url, size - oldn + n);
		if (!p)
			goto fail;
		f->a.url = p;

		if (str) {
			memmove(str, str + oldn, size - (f->metadata[xm] + oldn));
			for (enum Metadata m = 0; m < M_NB; ++m)
				if (f->metadata[xm] < f->metadata[m])
					f->metadata[m] -= oldn;
		}

		f->metadata[xm] = size - n;
		str = f->a.url + f->metadata[xm];
	}

	memcpy(str, buf, n);
}

static void
play_file(PlaylistFile pf)
{
	xassert(!pthread_rwlock_wrlock(&cur_rwlock));

	/* If we would like to do it very professionally we should have to
	 * measure the elapsed time between to seeks. */
	cur_out.cache_level /= 2;

	if (!sought && 0 <= cur_in.fd) {
		int64_t clock = cur_out.s.codec_ctx ? master_pts / cur_out.s.codec_ctx->sample_rate : 0;
		int64_t total = cur_in.s.format_ctx ? cur_in.s.format_ctx->duration : AV_NOPTS_VALUE;
		total = AV_NOPTS_VALUE != total ? total / AV_TIME_BASE : 0;
		unsigned percent = total ? clock * 100 / total : 0;

		if (percent < 20)
			/* Ignore. */;
		else if (percent < 80)
			increment_xattr(&cur_in, XATTR_SKIP_COUNT, M_skip_count);
		else
			increment_xattr(&cur_in, XATTR_PLAY_COUNT, M_play_count);
	}
	sought = 0;

	close_input(&cur_in);

	cur_in.pf = pf;
	master_pts = AV_NOPTS_VALUE;

	if (!pf.f) {
		next_cmd = '.';
		fprintf(tty, "\e[1;31mNo file to play\e[m"LF);
		goto fail;
	}

	if (open_input(&cur_in) < 0 ||
	    open_output(output_name, NULL, &cur_out, &cur_in) < 0 ||
	    init_resampler(&cur_in.resampler, cur_in.s.codec_ctx, cur_out.s.codec_ctx) < 0)
		goto fail;

	update_cover(&cur_in);

	fputs(CR, tty);

	/* Automatically unpause. */
	if ('.' == next_cmd) {
		next_cmd = 'n';
		paused = 0;
	}

	if (auto_w)
		print_around(cur_in.pf);
	if (auto_i)
		print_format(tty);
	print_now_playing();
	print_file(cur_in.pf, tty);

fail:
	xassert(!pthread_mutex_lock(&cur_out.fifo_mutex));
	cur_out.fifo_stopped = 0;
	if (cur_out.fifo)
		av_audio_fifo_reset(cur_out.fifo);
	/* TODO: Reset cache based on how many seconds have been played from last file. */
	xassert(!pthread_cond_signal(&cur_out.fifo_cond));
	xassert(!pthread_mutex_unlock(&cur_out.fifo_mutex));

	xassert(!pthread_rwlock_unlock(&cur_rwlock));
}

static void
handle_sigwinch(int sig)
{
	(void)sig;

	struct winsize w;
	term_height = !ioctl(fileno(tty), TIOCGWINSZ, &w) ? w.ws_row : 0;
}

static void
handle_sigcont(int sig)
{
	(void)sig;
	setup_tty();
}

static void
handle_sigexit(int sig)
{
	(void)sig;
	exit(EXIT_SUCCESS);
}

static int
spawn(void)
{
	fputs("\e[K", tty);
	fflush(tty);

	pid_t pid;
	if (!(pid = fork())) {
		restore_tty();

		struct sigaction sa;
		sigemptyset(&sa.sa_mask);

		sa.sa_handler = SIG_DFL;

		sigaction(SIGCONT, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGPIPE, &sa, NULL);

		pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL);
		return 0;
	}

	FILE *saved_tty = tty;
	tty = NULL;

	int rc;
	for (;;) {
		int status;
		if (waitpid(pid, &status, 0) < 0) {
			rc = -1;
			break;
		}

		rc = WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status) ? 1 : -1;
		break;
	}

	tty = saved_tty;
	setup_tty();

	return rc;
}

static void
open_visual_search(Playlist *parent, Playlist *playlist)
{
	char tmpname[] = "/tmp/muckXXXXXX";
	int fd = mkostemp(tmpname, O_CLOEXEC);
	if (fd < 0)
		return;

	FILE *stream = fdopen(fd, "w");
	fprintf(stream, "%s\n\n", last_search ? last_search : "");

	File const *cur = cur_in.pf.f;
	Playlist const *cur_playlist = cur_in.pf.p;
	for (enum MetadataX m = 0; m < MX_NB; ++m) {
		char const *value = cur ? get_metadata(cur_playlist, cur, m) : NULL;
		if (!value || !*value)
			continue;

		fputc(METADATA_LETTERS[m], stream);
		fputc('=', stream);
		fputc('\'', stream);
		fputs(value, stream);
		fputc('\'', stream);
		fputc('\n', stream);
	}
	fputc('\n', stream);

	char const *pathname = get_config_path("search-history");
	FILE *history = fopen(pathname, "re");
	if (history) {
		char buf[BUFSIZ];
		size_t buf_size;
		while (0 < (buf_size = fread(buf, 1, sizeof buf, history)))
			fwrite(buf, 1, buf_size, stream);
		fclose(history);
	} else
		fprintf(stream, "# %s is not found.\n"
				"#\n"
				"# Write any text into it to show here.\n",
				pathname);
	fputc('\n', stream);

	fprintf(stream,
			"# SYNTAX\n"
			"# ======\n"
			"#\n"
			"# FIRST-LINE ::= QUERY\n"
			"# QUERY ::= { [KEY]...[<][>][!][=][VALUE] } ...\n"
			"# VALUE ::= ' WORDS... '\n"
			"# VALUE ::= \" WORD... \"\n"
			"# VALUE ::= WORD\n"
			"# KEY ::= {\n"
			);
	for (enum MetadataX m = 0; m < MX_NB; ++m) {
		char const *value = cur ? get_metadata(cur_playlist, cur, m) : NULL;
		fprintf(stream, "#   %c=%-*s%s\n",
				METADATA_LETTERS[m],
				value && *value ? (int)sizeof METADATA_NAMES[m] : 0,
				METADATA_NAMES[m],
				value ? value : "");
	}
	fprintf(stream,
			"# }\n"
			"#\n"
			"# If a VALUE is omitted it is taken from the currently playing track.\n"
			"#\n"
			"# If a KEY is omitted it defaults to TITLE, CONTRIBUTOR... .\n"
			"# When multiple KEYs are present they are ORed.\n"
			"#\n"
			"# <, > Perform pairwise integer comparsion. Ignore every non-digit.\n"
			"#\n"
			"# !    Negate.\n"
			"#\n"
			"# =    Allow equality or perform regular expression match over strings (default).\n"
			"#\n"
			"# EXAMPLES\n"
			"# =======\n"
			"#\n"
			"# MP3s from albums and tracks containing \"House\" with contribution from \"DJ Bob\" and \"Alice?number?\" from year 2000:\n"
			"#   o'mp3' House y2000 '^dj BOB$' ^Alice[0-9]+$\n"
			"#\n"
			"# \"DJ Alice\"'s tracks in period:\n"
			"#   axf\"DJ Alice\" y>='1970.03 14' y<1970-12\n"
			"#\n"
			"# Albums and tracks beginning with \"March\":\n"
			"#   aA^March\n"
			"#\n"
			"# All versions of this track:\n"
			"#   a t\n"
			"#\n"
			"# Tracks from this album:\n"
			"#   A T V\n"
			"#\n"
			"# Tracks from this year:\n"
			"#   y\n"
			);

	fclose(stream);

	int rc = spawn();
	if (!rc) {
		char const *editor = getenv("EDITOR");
		execlp(editor, editor, "--", tmpname, NULL);
		_exit(127);
	} else if (0 < rc) {
		stream = fopen(tmpname, "re");

		char *line = NULL;
		size_t line_size = 0;
		ssize_t line_len;

		if (stream) {
			line_len = getline(&line, &line_size, stream);
			if (line_len < 0) {
				free(line);
				line = NULL;
			}
			fclose(stream);
		}

		if (line) {
			if (0 < line_len && '\n' == line[line_len - 1])
				line[line_len - 1] = '\0';

			free(last_search);
			last_search = line;
			search_file(parent, playlist, 0, line);
			/* free(line); */
		}
	}

	unlink(tmpname);
}

static int64_t
use_number(int64_t *pnumber)
{
	if (has_number)
		*pnumber = cur_number;
	else
		cur_number = *pnumber;
	return *pnumber;
}

static void
print_yesno(char const *msg, int yes)
{
	fprintf(tty, "%s: \e[%s\e[m"LF, msg, yes ? "1;32mYes" : "31mNo");
}

static void
pause_player(int pause)
{
	xassert(!pthread_rwlock_wrlock(&cur_rwlock));
	paused = pause;

	if (cur_in.s.format_ctx) {
		int rc = (paused ? av_read_pause : av_read_play)(cur_in.s.format_ctx);
		if (rc < 0 && AVERROR(ENOSYS) != rc)
			av_log(cur_in.s.format_ctx, AV_LOG_ERROR,
					"Could not %s stream: %s\n",
					paused ? "pause" : "play",
					av_err2str(rc));
	}

	if (!paused) {
		xassert(!pthread_mutex_lock(&cur_out.fifo_mutex));
		xassert(!pthread_cond_broadcast(&cur_out.fifo_cond));
		xassert(!pthread_mutex_unlock(&cur_out.fifo_mutex));
	}
	xassert(!pthread_rwlock_unlock(&cur_rwlock));
}

static struct timespec
get_file_mtim(PlaylistFile pf)
{
	struct stat st;
	return fstatat(pf.p->dirfd, pf.f->a.url, &st, 0)
		? st.st_mtim
		: (struct timespec){ 0 };
}

static void
do_cmd(char c)
{
	if ('0' <= c && c <= '9') {
		cur_number = 10 * (has_number ? cur_number : 0) + (c - '0');
		has_number = 1;
		return;
	} else if ('-' == c) {
		if (has_number)
			cur_number = -cur_number;
		return;
	}

	if (CONTROL('J') == c)
		c = next_cmd;

	PlaylistFile pf;
	switch (c) {
	case CONTROL('['):
		/* Noop. */
		break;

	case 'S': /* Statistics. */
	{
		Stat s;
		calc_stat(&s);
#define I "%20"PRIu64
#define I2 I " " I
#define A2(what) s.filtered.what, s.total.what
#define D(seconds) seconds / (3600 * 24), (unsigned)(seconds / 3600 % 24), (unsigned)(seconds / 60 % 60), (unsigned)(seconds % 60)
#define PRIduration "%6"PRIu64" days %02u:%02u:%02u"
		fprintf(tty,
				"                        FILTERED                TOTAL"LF
				"Files     : "I2"\n"
				"Playlists : "I2"\n"
				"Duration  : "PRIduration" "PRIduration"\n"
				"Unscanned : "I2"\n"
				"Untagged  : "I2"\n",
				A2(nb_files),
				A2(nb_playlists),
				D(s.filtered.duration), D(s.total.duration),
				A2(nb_unscanned),
				A2(nb_untagged));

#undef I
#undef I2
#undef A2
#undef D
#undef PRIduration
	}
		break;

	case 'I':
		print_yesno("Auto i", (auto_i ^= 1));
		if (!auto_i)
			break;
		/* FALLTHROUGH */
	case 'i': /* Information. */
		print_format(tty);
		print_file(cur_in.pf, tty);
		break;

	case 'm': /* Metadata. */
	{
		int old_level = av_log_get_level();
		av_log_set_level(AV_LOG_DEBUG);
		av_dump_format(cur_in.s.format_ctx, 0, cur_in.pf.f->a.url, 0);
		av_log_set_level(old_level);
	}
		break;

	case '&':
	case '!':
		print_yesno("Live", (live ^= 1));
		break;

	case 't': /* Tracks. */
		/* TODO: Implement track switching. */
		break;

	case 'f': /* Find. */
	case '/':
	case '=':
		open_visual_search(NULL, &master);
		if (live) {
			pf = seek_playlist(&master, NULL, 0, SEEK_CUR);
			if (pf.f != cur_in.pf.f)
				goto play_file;
		}
		break;

	case '|':
		/* TODO: Plumb master playlist. */
	case 'e': /* Edit. */
	{
		char tmpname[] = "/tmp/muckXXXXXX";
		int fd = mkostemp(tmpname, O_CLOEXEC);
		if (fd < 0)
			break;
		FILE *stream = fdopen(fd, "w");
		/* TODO: Edit currently playing playlist. Can be used
		 * to manually deselect files. Never touches real
		 * playlist. */
		plumb_file(&master.a, cur_filter[live], stream);
		fclose(stream);

		if (!spawn()) {
			char const *editor = getenv("EDITOR");
			execlp(editor, editor, "--", tmpname, NULL);
			_exit(127);
		}

		unlink(tmpname);
	}
		break;

	case 'r': /* Random. */
		next_cmd = c;
		pf = seek_playlist(&master, NULL, POS_RND, SEEK_SET);
		goto play_file;

	case 's': /* Set. */
	{
		static int64_t s_number = 0;

		pf = seek_playlist(&master, NULL, use_number(&s_number), SEEK_SET);
		goto play_file;
	}

	case 'n': /* Next. */
	case 'N':
	case 'p': /* Previous. */
	{
		static int64_t n_number = 1;

		use_number(&n_number);
		next_cmd = c;
		pf = seek_playlist(&master, NULL, 'n' == c ? n_number : -n_number, SEEK_CUR);
	play_file:;
		play_file(pf);
	}
		break;

	case 'g': /* Go to. */
	{
		static int64_t g_number = 0;

		next_cmd = c;
		seek_player(use_number(&g_number), SEEK_SET);
	}
		break;

	case 'G': /* GO TO. */
	{
		static int64_t G_number = 100 * 3 / 8;

		if (AV_NOPTS_VALUE != cur_in.s.format_ctx->duration)
			seek_player(av_rescale_q_rnd(cur_in.s.format_ctx->duration,
						AV_TIME_BASE_Q,
						(AVRational){ 100, use_number(&G_number) } /* PHI */, AV_ROUND_DOWN), SEEK_SET);
	}
		break;

	case 'h':
	case 'l':
		seek_player('h' == c ? -5 : +5, SEEK_CUR);
		break;

	case 'j':
	case 'k':
	{
		int64_t step = av_rescale(
				AV_NOPTS_VALUE != cur_in.s.format_ctx->duration
					? cur_in.s.format_ctx->duration
					: 0,
				1, AV_TIME_BASE * 16);
		step = FFMAX(step, +5);

		seek_player('j' == c ? -step : step, SEEK_CUR);
	}
		break;


	case 'W':
		print_yesno("Auto w", (auto_w ^= 1));
		if (!auto_w)
			break;
		/* FALLTHROUGH */
	case 'w': /* Where. */
		xassert(!pthread_rwlock_rdlock(&cur_rwlock));
		print_around(cur_in.pf);
		xassert(!pthread_rwlock_unlock(&cur_rwlock));
		break;

	case '.':
	case 'c': /* Continue. */
	case '>':
		pause_player('.' == c);
		break;

	case ' ':
		pause_player(!paused);
		break;

	case 'Z': /* Zzz. */
	case 'Q':
	case 'q':
		exit(EXIT_SUCCESS);

	case 'a': /* After. */
	case 'b': /* Before. */
		/* TODO: Put current file at the beginning/at the end
		 * of the selected playlist. Choosing "."/"#" places
		 * before/after currently playing file. */
		break;

	case 'A':
	case 'B':
		/* TODO: Just like "a" but for all filtered files. */
		break;

	default:
	{
		if (!(' ' <= (unsigned)c && (unsigned)c <= '~'))
			break;

		pf = cur_in.pf;
		struct timespec mtim_before = get_file_mtim(pf);

		if (!spawn()) {
			Playlist *playlist = pf.p;
			File *f = pf.f;

			if (playlist &&
			    AT_FDCWD != playlist->dirfd &&
			    fchdir(playlist->dirfd) < 0)
			{
				fprintf(tty, "\e[1;31mCould not change working directory\e[m");
				fflush(tty);
				_exit(127);
			}

			if (F_FILE == f->a.type)
				setenv("MUCK_PATH", f->a.url, 0);

			char name[5 + sizeof *METADATA_NAMES] = "MUCK_";

			for (enum MetadataX m = 0; m < MX_NB; ++m) {
				memcpy(name + 5, METADATA_NAMES[m], sizeof *METADATA_NAMES);
				char const *value = get_metadata(playlist, f, m);
				if (value)
					setenv(name, f->a.url + f->metadata[m], 0);
			}

			char filename[2] = { c };
			execl(get_config_path(filename), filename, pf.f->a.url, NULL);
			fprintf(tty, "\e[1;31mNo binding for '%c'\e[m\n", c);

			_exit(127);
		}

		struct timespec mtim_after = get_file_mtim(pf);

		if (memcmp(&mtim_before, &mtim_after, sizeof mtim_before)) {
			fprintf(tty, "Reloading changed file..."CR);
			fflush(tty);
			play_file(pf);
		}
	}
		break;
	}

	has_number = 0;
}

static void
do_cmd_str(char const *s)
{
	while (*s)
		do_cmd(*s++);
}

static void
process_args(int argc, char **argv, int late)
{
	optind = 1;
	for (int c; 0 <= (c = getopt(argc, argv, "c:C:dl:o:w"));) {
		if (!late) switch (c) {
		case 'd':
			debug = 1;
			break;

		case 'l':
			av_log_set_level(atoi(optarg));
			break;

		case 'o':
			output_name = optarg;
			break;

		case 'w':
			writable = 1;
			break;

		case 'C':
			do_cmd_str(optarg);
			break;

		case ':':
		case '?':
			exit(EXIT_FAILURE);
		} else switch (c) {
		case 'c':
			do_cmd_str(optarg);
			break;
		}
	}
}

static void
open_args(int argc, char **argv)
{
	master.a.type = F_PLAYLIST;
	master.first_child_playlist = SIZE_MAX;
	init_file(&master.a, "master");
	master.read_only = 1;
	master.dirfd = AT_FDCWD;
	master.mnemonic = '.';

	if (argc <= optind) {
		Playlist *playlist = append_file(&master, F_PLAYLIST);
		init_file(&playlist->a, "stdin");
		read_file(&master, &playlist->a);
		read_playlist(playlist, STDIN_FILENO);
	} else for (; optind < argc; ++optind) {
		char const *url = argv[optind];
		enum FileType type = probe_url(&master, url);
		AnyFile *a = append_file(&master, type);
		init_file(a, url);
		read_file(&master, a);
	}
}

static void
log_cb(void *ctx, int level, const char *format, va_list ap)
{
	(void)ctx;

	if (av_log_get_level() < level || !tty)
		return;

	if (level <= AV_LOG_ERROR)
		fputs("\e[1;31m", tty);
	vfprintf(tty, format, ap);
	if (level <= AV_LOG_ERROR)
		fputs("\e[m", tty);
}

int
main(int argc, char **argv)
{
	if (!(tty = fopen(ctermid(NULL), "w+e"))) {
		fprintf(stderr, "Cannot connect to TTY\n");
		return EXIT_FAILURE;
	}

	atexit(do_cleanup);

	save_tty();
	setup_tty();

	/* Setup signals. */
	{
		struct sigaction sa;
		sa.sa_flags = SA_RESTART;
		/* Block all signals. */
		xassert(!sigfillset(&sa.sa_mask));
		pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL);

		sa.sa_handler = handle_sigcont;
		xassert(!sigaction(SIGCONT, &sa, NULL));

		sa.sa_handler = handle_sigwinch;
		xassert(!sigaction(SIGWINCH, &sa, NULL));
		handle_sigwinch(SIGWINCH);

		sa.sa_handler = handle_sigexit;
		xassert(!sigaction(SIGINT, &sa, NULL));
		xassert(!sigaction(SIGHUP, &sa, NULL));
		xassert(!sigaction(SIGTERM, &sa, NULL));
		xassert(!sigaction(SIGQUIT, &sa, NULL));

		sa.sa_handler = SIG_IGN;
		xassert(!sigaction(SIGPIPE, &sa, NULL));
	}

	/* Setup FFmpeg. */
	av_log_set_callback(log_cb);
	av_log_set_level(AV_LOG_ERROR);

	avdevice_register_all();

	/* Setup vital locks. */
	{
		pthread_rwlockattr_t attr;
		xassert(!pthread_rwlockattr_init(&attr));
#if HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP
		/* Prioritize wrlocks (user actions) over rdlocks. */
		xassert(!pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP));
#endif
		xassert(!pthread_rwlock_init(&cur_rwlock, &attr));
		xassert(!pthread_rwlockattr_destroy(&attr));
		xassert(!pthread_mutex_init(&cur_out.fifo_mutex, NULL));
		xassert(!pthread_cond_init(&cur_out.fifo_cond, NULL));
	}

	/* Sanitize environment. */
	if (!getenv("MUCK_HOME")) {
		char pathname[PATH_MAX];
		snprintf(pathname, sizeof pathname, "%s/.config/muck",
				getenv("HOME"));
		xassert(!setenv("MUCK_HOME", pathname, 0));
	}

	xassert(0 <= rnd_init(&rnd));

	/* Setup internal communication channel. */
	if (pipe2(control, O_CLOEXEC) < 0)
		fprintf(tty, "\e[1;31mCould not open control channel: %s\e[m\n",
				strerror(errno));

	/* Start workers. */
	{
		pthread_attr_t attr;
		struct sched_param sp;

		if (pthread_attr_init(&attr) ||
		    pthread_attr_setschedpolicy(&attr, SCHED_FIFO) ||
		    (sp.sched_priority = sched_get_priority_max(SCHED_FIFO)) < 0 ||
		    pthread_attr_setschedparam(&attr, &sp) ||

		    pthread_create(&source_thread, &attr, source_worker, NULL) ||
		    pthread_create(&sink_thread, &attr, sink_worker, NULL) ||

		    pthread_attr_destroy(&attr))
		{
			fprintf(tty, "\e[1;31mCould not create worker thread: %s\e[m\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		threads_inited = 1;
	}

	/* Setup ended, can load files now. */

	process_args(argc, argv, 0);
	open_args(argc, argv);
	process_args(argc, argv, 1);

	/* If nothing has been started playing by the user, automatically begin
	 * playing the first file. */
	if (!cur_in.pf.f) {
		PlaylistFile pf;
		pf = seek_playlist(&master, NULL, 0, SEEK_SET);
		play_file(pf);
	}

	/* TUI event loop. */
	{
		struct pollfd fds[2];
		/* Either read user input... */
		fds[0].fd = fileno(tty);
		fds[0].events = POLLIN;

		/* ...or the internal channel, used to auto play next track. */
		fds[1].fd = control[R];
		fds[1].events = POLLIN;

		sigset_t sigmask;
		xassert(!sigemptyset(&sigmask));

		for (;;) {
			print_progress(1);
			fflush(tty);

			int rc = ppoll(fds, ARRAY_SIZE(fds), NULL, &sigmask);
			if (rc <= 0)
				continue;

			char c;
			if (1 != read(fds[!(POLLIN & fds[0].revents)].fd, &c, 1))
				break;

			do_cmd(c);
		}
	}
}
