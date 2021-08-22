#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdatomic.h>
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
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavformat/avformat.h>
#include <libavformat/url.h>
#include <libavutil/channel_layout.h>
#include <libavutil/frame.h>

#include "config.h"

#include "birdlock.h"

#include "rnd.h"

#ifndef NDEBUG
# define xassert(c) assert(c)
#else
# define xassert(c) ((void)(c))
#endif

#ifdef HAVE___BUILTIN_EXPECT
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) x
# define unlikely(x) x
#endif

#define ARRAY_SIZE(x) (sizeof x / sizeof *x)

#define PTR_INC(pp, n) (pp) = (void *)((char *)(pp) + (n))

#define CONTROL(c) ((c) - '@')

#define NS_PER_SEC 1000000000

#define atomic_store_lax(...) atomic_store_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_load_lax(...) atomic_load_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_sub_lax(...) atomic_fetch_sub_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_add_lax(...) atomic_fetch_add_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_exchange_lax(...) atomic_exchange_explicit(__VA_ARGS__, memory_order_relaxed)

/* Line-feed that must be used when printing the first line after printing into
 * a dirty terminal line, i.e. after print_progress or editor has been closed. */
#define LF "\e[K\n"
#define CR "\e[K\r"

#define IS_SUFFIX(haystack, needle) \
	(strlen(needle) <= haystack##_size && \
	 !memcmp(haystack + haystack##_size - strlen(needle), needle, strlen(needle)) && \
	 (haystack##_size -= strlen(needle), 1))

static char const XATTR_COMMENT[] = "user.comment";
static char const XATTR_PLAY_COUNT[] = "user.play_count";
static char const XATTR_SKIP_COUNT[] = "user.skip_count";
static char const XATTR_TAGS[] = "user.tags";

#define ALIGNED_ATOMIC _Alignas(64)

#define COMPRESSORS \
	/* xmacro(tail, program) */ \
	xmacro(".bz", "bzip2") \
	xmacro(".bz2", "bzip2") \
	xmacro(".gz", "gzip") \
	xmacro(".lz4", "lz4") \
	xmacro(".xz", "xz") \
	xmacro(".zst", "zstd")

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

#define for_each_file(const) \
	for (size_t offset = 0; offset < playlist->files_size;) \
		for (AnyFile const *a = (void *)((char *)playlist->files + offset); \
		     a; \
		     offset += get_file_size(a->type), a = NULL)

#define for_each_playlist(playlist, parent) \
	for (Playlist *playlist = SIZE_MAX == parent->first_child_playlist \
		? NULL \
		: (void *)((char *)parent->files + parent->first_child_playlist); \
	     playlist; \
	     playlist = SIZE_MAX == playlist->next_sibling_playlist \
		? NULL \
		: (void *)((char *)playlist + playlist->next_sibling_playlist))

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

typedef struct {
	Playlist *p;
	File *f;
} PlaylistFile;

enum { CLAUSE_LEVEL_MAX = 10, };

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

typedef struct {
	struct {
		uint64_t nb_files;
		uint64_t nb_playlists;
		uint64_t duration;
		uint64_t nb_unscanned;
		uint64_t nb_untagged;
	} total, filtered;
} Stat;

typedef struct {
	AVFormatContext *format_ctx;
	AVCodecContext *codec_ctx;
	AVStream *audio;
} Stream;

#define INPUT_INITIALIZER (Input){ .fd = -1, }

typedef struct {
	Stream s;
	AVStream *cover_front;
	PlaylistFile pf;
	int fd; /**< -1 for F_URL. */
	unsigned nb_audios;
} Input;

static pthread_t source_thread, sink_thread;
#if CONFIG_VALGRIND
static int threads_inited;
static atomic_uchar ALIGNED_ATOMIC terminate;
#endif
static int control[2];

static char const *ocodec = "pcm";
static char const *oformat_name = "alsa";
static char const *ofilename = NULL;

static Input in0 = INPUT_INITIALIZER;
static Stream out;
static unsigned _Atomic cur_track;

static struct {
	BirdLock lock;
	char buf[2][128];
} source_info, sink_info;

static char const *graph_descr = "volume=replaygain=track";

static AVFilterGraph *graph;
static AVFilterContext *buffer_ctx, *buffersink_ctx;
static atomic_int ALIGNED_ATOMIC volume = 100; /**< Desired volume. */
static int graph_volume_volume; /**< Configured state of [volume]volume= */

/**
 * To notify a resting thread:
 * - Producer: Buffer needs to be refilled again.
 * - Consumer: New frames available after buffer being emptied.
 */
static pthread_cond_t buffer_wakeup = PTHREAD_COND_INITIALIZER;
/**
 * Only to protect buffer_wakeup. buffer_* uses atomic (i.e. lockless) operations
 * otherwise.
 */
static pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;
/**
 * What is being buffered.
 */
static int64_t _Atomic ALIGNED_ATOMIC buffer_bytes;
static int64_t buffer_bytes_max = 8 /* MB */ << 20;
static int64_t _Atomic buffer_full_bytes;
static enum SourceState {
	SS_RUNNING,
	SS_WAITING,
	SS_STOPPED, /* Avoid nagging source for more. */
} _Atomic ALIGNED_ATOMIC source_state;

/**
 * Producer buffer: Cyclic list of AVFrames.
 */
static AVFrame *buffer[UINT16_MAX + 1];
static uint16_t _Atomic ALIGNED_ATOMIC buffer_head;
static uint16_t _Atomic ALIGNED_ATOMIC buffer_tail;
/**
 * buffer_hair..buffer_head: Maybe alloced, reusable frames.
 * buffer_tail..buffer_hair: NULLs.
 */
static uint16_t buffer_hair;

static int64_t _Atomic ALIGNED_ATOMIC cur_pts, cur_duration;
static atomic_uchar ALIGNED_ATOMIC paused;

static pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER; /**< Only for non-main threads. */
static Playlist master;

static uint8_t cur_filter[2]; /**< .[live] is the currently used filter. */
/* TODO: Queue is live queue has p=^queue$ filter. In non-live mode we can select tracks etc. */
static atomic_uchar live = 1;
static atomic_uchar auto_w, auto_i;

static char *search_history[10];

static char seek_cmd = 'n';
static RndState rnd;
static File *seek_file0;
static int64_t _Atomic seek_file_pts = AV_NOPTS_VALUE;
static int64_t _Atomic seek_pts = AV_NOPTS_VALUE;

static int has_number;
static int64_t cur_number;

struct termios saved_termios;
static int win_height;
static FILE *tty;

static int writable;

static char const *
get_playlist_name(Playlist const *playlist)
{
	return playlist->name ? playlist->name : playlist->a.url;
}

static void
print_error(char const *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	flockfile(tty);
	fputs("\e[1;31m", tty);
	vfprintf(tty, msg, ap);
	fputs("\e[m\n", tty);
	funlockfile(tty);
	va_end(ap);
}

static void
print_file_error(Playlist const *parent, AnyFile const *a, char const *msg, char const *error_msg)
{
	char const *url = ((AnyFile const *)a)->url;
	print_error(
			"%s%s"
			"%s: %s"
			"%s%s",
			parent ? get_playlist_name(parent) : "",
			parent ? "/" : "",

			url ? url : "?",
			msg,

			error_msg ? ": " : "",
			error_msg ? error_msg : ""
	);
}

static void
print_file_averror(Playlist const *parent, AnyFile const *a, char const *msg, int err)
{
	print_file_error(parent, a, msg, av_err2str(err));
}

static void
print_file_strerror(Playlist const *parent, AnyFile const *a, char const *msg)
{
	print_file_error(parent, a, msg, strerror(errno));
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

#define xmacro(tail, program) || IS_SUFFIX(url, tail)
	enum FileType playlist_type = 0 COMPRESSORS
		? F_PLAYLIST_COMPRESSED
		: F_PLAYLIST;
#undef xmacro

	return
		IS_SUFFIX(url, ".m3u") ||
		IS_SUFFIX(url, ".m3u8") ||
		IS_SUFFIX(url, ".pl")
			? playlist_type
			: F_FILE;
}

static char const *
probe_compressor(char const *url)
{
	size_t url_size = strlen(url);

#define xmacro(tail, program) if (IS_SUFFIX(url, tail)) return program;
	COMPRESSORS
#undef xmacro

	abort();
}

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

#if CONFIG_VALGRIND
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
#endif

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

		playlist->mnemonic = '\0';
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
				error_msg = "Too long line";
				goto out;
			}

			ssize_t len = read(fd, buf + buf_size, sizeof buf - buf_size);
			if (len < 0) {
				error_msg = "Could not read playlist stream";
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
				if (playlist->dirfd < 0) {
					error_msg = "Could not open directory of playlist";
					goto out;
				}
			} else if (IS_DIRECTIVE("PLAYLIST:")) {
				if (playlist->files_size)
					goto fail_used_too_late;

				free(playlist->name);
				if (!(playlist->name = strdup(col))) {
				fail_enomem:
					print_file_strerror(playlist->parent, &playlist->a,
							"Could not allocate memory");
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
				goto fail_enomem;
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
		print_file_strerror(NULL, a, "Could not allocate memory");
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
		print_file_strerror(parent, a, "Cannot open file");
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
reap(pid_t pid, char const *program)
{
	int status;
	xassert(0 <= waitpid(pid, &status, 0));

	if (!(WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status)))
		print_error("Program %s terminated with failure", program);
}

static void
compress_playlist(Playlist *playlist, int *pfd, pid_t *ppid, char const **pprogram, int do_compress)
{
	int pipes[2] = { -1, -1 };

	*pprogram = probe_compressor(playlist->a.url);

	pipe2(pipes, O_CLOEXEC);

	if ((*ppid = fork()) < 0) {
		print_file_strerror(playlist->parent, &playlist->a,
				do_compress
					? "Could not compress playlist"
					: "Could not decompress playlist");
	} else if (!*ppid) {
		if (dup2(do_compress ? pipes[0] : *pfd, STDIN_FILENO) < 0 ||
		    dup2(do_compress ? *pfd : pipes[1], STDOUT_FILENO) < 0 ||
		    execlp(*pprogram, *pprogram, "-c", do_compress ? NULL : "-d", NULL) < 0)
			print_file_strerror(playlist->parent, &playlist->a,
					do_compress
						? "Could not compress playlist"
						: "Could not decompress playlist");
		_exit(127);
	}

	close(pipes[!do_compress]);
	close(*pfd);
	*pfd = pipes[do_compress];
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
		char const *program = probe_compressor(playlist->a.url);
		pid_t pid = -1;

		if (F_PLAYLIST_COMPRESSED == playlist->a.type)
			compress_playlist(playlist, &fd, &pid, &program, 0);

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

		if (0 <= pid)
			reap(pid, program);
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
	if ((int)sizeof tmp_pathname <= n)
		goto fail_open;

	int dirfd = playlist->parent ? playlist->parent->dirfd : AT_FDCWD;
	int fd = openat(dirfd,
			tmp_pathname,
			O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (fd < 0) {
	fail_open:
		print_file_strerror(playlist->parent, &playlist->a,
				"Could not open temporary file");
		return;
	}

	char const *program;
	pid_t pid = -1;

	if (F_PLAYLIST_COMPRESSED == playlist->a.type)
		compress_playlist(playlist, &fd, &pid, &program, 1);

	FILE *stream = fdopen(fd, "w");
	if (!stream) {
		print_file_strerror(playlist->parent, &playlist->a,
				"Could not open playlist stream");
		return;
	}

	char buf[UINT16_MAX + 1];
	setbuffer(stream, buf, sizeof buf);

	write_playlist(playlist, stream);

	fflush(stream);
	if (ferror(stream)) {
		print_file_strerror(playlist->parent, &playlist->a,
				"Could not write playlist");
		fclose(stream);
		unlink(tmp_pathname);
		return;
	}
	fclose(stream);

	if (0 <= pid)
		reap(pid, program);

	if (renameat(dirfd, tmp_pathname, dirfd, playlist->a.url) < 0) {
		unlink(tmp_pathname);
		print_file_strerror(playlist->parent, &playlist->a,
				"Could not replace existing playlist");
		return;
	}
}

static void
close_output(void)
{
	if (out.format_ctx) {
		int rc = av_write_trailer(out.format_ctx);
		if (rc < 0)
			av_log(out.format_ctx, AV_LOG_ERROR,
					"Could not write output file trailer: %s\n",
					av_err2str(rc));
	}

	if (out.codec_ctx)
		avcodec_free_context(&out.codec_ctx);
	if (out.format_ctx) {
		avio_closep(&out.format_ctx->pb);
		avformat_free_context(out.format_ctx);
	}
}

static void
close_graph(void)
{
	avfilter_graph_free(&graph);
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
				av_rescale(duration, 1, AV_TIME_BASE)) + 1 /* NUL */;
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

				for (; --n; ++dest, ++src)
					*dest = (unsigned char)*src < ' ' ? ' ' : *src;

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

	AVStream const *stream = in->cover_front;
	if (stream) {
		AVPacket const *pic = &stream->attached_pic;
		data = pic->data;
		data_size = pic->size;
	} else {
		static uint8_t const DEFAULT_COVER[] =
		{
#include "cover.png.h"
		};

		data = DEFAULT_COVER;
		data_size = sizeof DEFAULT_COVER;
	}

	ftruncate(fd, data_size);

	p = mmap(NULL, data_size, PROT_WRITE, MAP_SHARED, fd, 0);
	if (MAP_FAILED != p) {
		memcpy(p, data, data_size);
		munmap(p, data_size);
	} else {
		ftruncate(fd, 0);
	}

	/* Notify programs about changing. */
	futimens(fd, NULL /* Now. */);

	close(fd);
}

static void
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
			return;
		sprintf(urlbuf, "pipe:%d", in->fd);
		url = urlbuf;
	}

	int rc;

	rc = avformat_open_input(&in->s.format_ctx, url, NULL, NULL);
	if (rc < 0) {
		print_file_averror(playlist, &f->a,
				"Could not open input stream", rc);
		return;
	}

	/* Get information on the input file (number of streams etc.). */
	(void)avformat_find_stream_info(in->s.format_ctx, NULL);

	in->cover_front = NULL;
	in->s.audio = NULL;

	unsigned nb_audios = 0;

	for (unsigned i = 0; i < in->s.format_ctx->nb_streams; ++i) {
		AVStream *stream = in->s.format_ctx->streams[i];

		stream->discard = AVDISCARD_ALL;

		if (AVMEDIA_TYPE_AUDIO == stream->codecpar->codec_type) {
			if (cur_track == nb_audios++)
				in->s.audio = stream;
			continue;
		}

		if ((AV_DISPOSITION_ATTACHED_PIC & stream->disposition) &&
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

	atomic_store_lax(&in->nb_audios, nb_audios);

	if (!in->s.audio) {
		print_file_error(playlist, &f->a, "No audio streams found", NULL);
		return;
	}

#if 0
	AVStream *default_stream = in->s.format_ctx->streams[av_find_default_stream_index(in->s.format_ctx)];
	if (default_stream->opaque)
		in->s.audio = default_stream;
#endif

	in->s.audio->discard = 0;

	const AVCodec *codec;

	/* Find a decoder for the audio stream. */
	if (!(codec = avcodec_find_decoder(in->s.audio->codecpar->codec_id))) {
		print_file_error(playlist, &f->a, "Could not find decoder", NULL);
		return;
	}

	/* Allocate a new decoding context. */
	if (!(in->s.codec_ctx = avcodec_alloc_context3(codec))) {
		print_file_error(playlist, &f->a, "Could not allocate codec", NULL);
		return;
	}

	/* Initialize the stream parameters with demuxer information. */
	rc = avcodec_parameters_to_context(in->s.codec_ctx, in->s.audio->codecpar);
	if (rc < 0) {
		print_file_averror(playlist, &f->a,
				"Could not initalize codec parameters", rc);
		return;
	}

	in->s.codec_ctx->time_base = in->s.audio->time_base;

	rc = avcodec_open2(in->s.codec_ctx, codec, NULL);
	if (rc < 0) {
		print_file_averror(playlist, &f->a, "Could not open codec", rc);
		return;
	}

	read_metadata(&in[0]);
}

static void
sbprintf(char **pbuf, int *pn, char const *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int rc = vsnprintf(*pbuf, *pn, format, ap);
	va_end(ap);

	assert(0 <= rc);
	if (*pn <= rc)
		rc = *pn;

	*pbuf += rc;
	*pn -= rc;
}

static void
print_stream(char **pbuf, int *pn, Stream const *s, int output)
{
	if (!s->codec_ctx) {
		sbprintf(pbuf, pn, "(none)");
		return;
	}

	char const *format_name = output
		? s->format_ctx->oformat->name
		: s->format_ctx->iformat->name;
	char const *codec_name = s->codec_ctx->codec->name;
	sbprintf(pbuf, pn, "%s(%s)", format_name, codec_name);

	if (!output && AV_NOPTS_VALUE != s->audio->duration) {
		int64_t duration = av_rescale(
				s->audio->duration,
				s->audio->time_base.num,
				s->audio->time_base.den);
		sbprintf(pbuf, pn, ", %3"PRId64":%02hu",
				duration / 60,
				(unsigned char)(duration % 60));
	}

	if (44100 != s->codec_ctx->sample_rate)
		sbprintf(pbuf, pn, ", %d Hz", s->codec_ctx->sample_rate);

	if (AV_CH_LAYOUT_STEREO != s->codec_ctx->channel_layout) {
		sbprintf(pbuf, pn, ", ");
		int k = (av_get_channel_layout_string(*pbuf, *pn,
				s->codec_ctx->channels, s->codec_ctx->channel_layout), strlen(*pbuf) /* Thanks. */);
		*pbuf += k;
		*pn -= k;
	}

	int64_t bit_rate = s->codec_ctx->bit_rate;
	if (!bit_rate)
		bit_rate = s->format_ctx->bit_rate;
	if (bit_rate)
		sbprintf(pbuf, pn, ", %"PRId64" kb/s", bit_rate / 1000);
}

static int
configure_graph(AVBufferSrcParameters *pars)
{
	int ret = 0;
	int rc;
	char const *error_msg = NULL;

	close_graph();

	graph = avfilter_graph_alloc();
	if (!graph) {
	fail_enomem:
		rc = AVERROR(ENOMEM);
		error_msg = "Could not allocate memory";
		goto out;
	}

	AVFilterInOut *src_end = NULL, *sink_end = NULL;

	graph->nb_threads = 1;

	AVFilterContext *format_ctx;

	if (!(buffer_ctx = avfilter_graph_alloc_filter(graph, avfilter_get_by_name("abuffer"), "src")) ||
	    !(format_ctx = avfilter_graph_alloc_filter(graph, avfilter_get_by_name("aformat"), "aformat")) ||
	    !(buffersink_ctx = avfilter_graph_alloc_filter(graph, avfilter_get_by_name("abuffersink"), "sink")))
		goto fail_enomem;

	av_buffersrc_parameters_set(buffer_ctx, pars);

	char buf[128];
	av_get_channel_layout_string(buf, sizeof(buf), 0, out.codec_ctx->channel_layout);
	xassert(0 <= av_opt_set(format_ctx, "channel_layouts", buf, AV_OPT_SEARCH_CHILDREN));
	xassert(0 <= av_opt_set(format_ctx, "sample_fmts", av_get_sample_fmt_name(out.codec_ctx->sample_fmt), AV_OPT_SEARCH_CHILDREN));
	snprintf(buf, sizeof buf, "%d", out.codec_ctx->sample_rate);
	xassert(0 <= av_opt_set(format_ctx, "sample_rates", buf, AV_OPT_SEARCH_CHILDREN));

	if ((rc = avfilter_init_str(buffer_ctx, NULL)) < 0 ||
	    (rc = avfilter_init_str(format_ctx, NULL)) < 0 ||
	    (rc = avfilter_init_str(buffersink_ctx, NULL)) < 0)
	{
		error_msg = "Cannot initialize filters";
		goto out;
	}

	if (!(src_end = avfilter_inout_alloc()) ||
	    !(sink_end = avfilter_inout_alloc()))
		goto fail_enomem;

	src_end->name = av_strdup("in");
	src_end->filter_ctx = buffer_ctx;
	/*
	 *   O
	 *   |
	 * User-supplied filtergraph.
	 *                         |
	 *                         O
	 */
	sink_end->name = av_strdup("out");
	sink_end->filter_ctx = format_ctx;

	if ((rc = avfilter_link(sink_end->filter_ctx, 0, buffersink_ctx, 0)) < 0) {
		error_msg = "Cannot create link";
		goto out;
	}

	rc = avfilter_graph_parse_ptr(graph, graph_descr,
				&sink_end, &src_end, NULL);
	if (rc < 0) {
		error_msg = "Cannot parse filtergraph";
		goto out;
	}

	if ((rc = avfilter_graph_config(graph, NULL)) < 0) {
		error_msg = "Cannot configure filtergraph";
		goto out;
	}

	graph_volume_volume = 100;

	if (AV_LOG_DEBUG <= av_log_get_level()) {
		char *str = avfilter_graph_dump(graph, NULL);
		av_log(graph, AV_LOG_DEBUG, "%s\n", str);
		av_free(str);
	}

out:
	if (error_msg) {
		print_error("%s: %s", error_msg, av_err2str(rc));
		ret = -1;
	}

	avfilter_inout_free(&src_end);
	avfilter_inout_free(&sink_end);

	return ret;
}

static void
update_output_info(void)
{
	char *buf = sink_info.buf[birdlock_wr_acquire(&sink_info.lock)];
	int n = sizeof sink_info.buf[0];
	print_stream(&buf, &n, &out, 1);
	birdlock_wr_release(&sink_info.lock);
}

static int
configure_output(AVFrame const *frame)
{
	AVCodec const *codec = !strcmp(ocodec, "pcm")
		? avcodec_find_encoder(av_get_pcm_codec(frame->format, -1))
		: avcodec_find_encoder_by_name(ocodec);
	if (!codec) {
		assert(!"no codec");
		return -1;
	}

	/* Configuration not changed. */
	if (out.codec_ctx &&
	    codec == out.codec_ctx->codec &&
	    out.codec_ctx->sample_rate == frame->sample_rate &&
	    out.codec_ctx->channels == frame->channels)
		return 0;

	close_output();

	update_output_info();

	int rc;

	rc = avformat_alloc_output_context2(&out.format_ctx, NULL, oformat_name, ofilename);
	if (rc < 0)
		return -1;

	if (!(AVFMT_NOFILE & out.format_ctx->oformat->flags)) {
		rc = avio_open(&out.format_ctx->pb, ofilename, AVIO_FLAG_WRITE);
		if (rc < 0)
			return -1;
	}

	AVStream *stream;
	/* Create a new audio stream in the output file container. */
	if (!(stream = avformat_new_stream(out.format_ctx, NULL)))
		return -1;

	if (!(out.codec_ctx = avcodec_alloc_context3(codec)))
		return -1;

	if (out.format_ctx->flags & AVFMT_GLOBALHEADER)
		out.codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	/* Set the basic encoder parameters.
	 * The input file's sample rate is used to avoid a sample rate conversion. */
	out.codec_ctx->channels = frame->channels;
	out.codec_ctx->channel_layout = av_get_default_channel_layout(out.codec_ctx->channels);
	out.codec_ctx->sample_rate = frame->sample_rate;
	out.codec_ctx->sample_fmt = codec->sample_fmts[0];
	out.codec_ctx->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;

	if (out.format_ctx->oformat->flags & AVFMT_GLOBALHEADER)
		out.codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	if (/* Open the encoder for the audio stream to use it later. */
	    (rc = avcodec_open2(out.codec_ctx, codec, NULL)) < 0 ||
	    (rc = avcodec_parameters_from_context(stream->codecpar, out.codec_ctx)) < 0 ||
	    (rc = avformat_write_header(out.format_ctx, NULL)) < 0)
		return -1;

	out.audio = out.format_ctx->streams[0];

	update_output_info();

	return 1;
}

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
print_file(File const *f, FILE *stream)
{
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

	uint64_t duration = f->metadata[M_duration]
		? strtoull(a->url + f->metadata[M_duration], NULL, 10)
		: 0;

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

static Playlist *
get_parent(Playlist *ancestor, AnyFile *a)
{
	if ((uintptr_t)a - (uintptr_t)ancestor->files < ancestor->files_size)
		return ancestor;

	for_each_playlist(child, ancestor) {
		Playlist *ret = get_parent(child, a);
		if (ret)
			return ret;
	}

	return NULL;
}

static PlaylistFile
get_current_pf(void)
{
	PlaylistFile ret;
	ret.f = atomic_load_lax(&in0.pf.f);
	ret.p = ret.f ? get_parent(&master, &ret.f->a) : NULL;
	return ret;
}

static AnyFile *
get_playlist_begin(Playlist const *playlist, int dir)
{
	return (void *)((char *)playlist->files + (
		0 <= dir
			? 0
			: playlist->files_size - get_file_size(playlist->last_child_type)
	));
}

static AnyFile *
get_playlist_end(Playlist const *playlist, int dir)
{
	return get_playlist_begin(playlist, -dir);
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
		PlaylistFile tmp;
		if (!cur) {
			tmp.f = atomic_load_lax(&in0.pf.f);
			tmp.p = tmp.f ? get_parent(&master, &tmp.f->a) : NULL;
			cur = &tmp;
		}
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
				a = get_playlist_begin(p, dir);
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
		while (playlist && get_playlist_end(playlist, dir) == a) {
			a = &playlist->a;
			playlist = ((Playlist *)a)->parent;
		}

		/* Wrap around. */
		if (!playlist) {
			playlist = (void *)a;
			a = get_playlist_begin(playlist, dir);
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
search_file(char const *s)
{
	Clause clauses[M_NB], *clause = clauses;
	char buf[1 << 12];

	char const *orig = s;
	char const *error_msg = NULL;
	char const *p;

	uint8_t level = 0;

	struct timespec start;
	xassert(!clock_gettime(CLOCK_MONOTONIC, &start));

	File const *cur = atomic_load_lax(&in0.pf.f);

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
			if (!cur) {
				error_msg = "No file is playing";
				goto cleanup;
			}

			for (uint64_t mxs = clause->mxs; mxs;) {
				enum MetadataX m = __builtin_ctz(mxs);
				mxs ^= UINT64_C(1) << m;

				p = cur->metadata[m] ? cur->a.url + cur->metadata[m] : "";
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

	uint8_t filter_index = 0;
	match_file(NULL, &master.a, filter_index, clauses, clause - clauses);

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

static int progress_printed = 0;

static void
print_progress(int force)
{
	if (!tty)
		return;

	static int64_t _Atomic old_clock = 0, old_duration = 0;

	int64_t clock = atomic_load_lax(&cur_pts);
	int64_t duration = atomic_load_lax(&cur_duration);

	/* Maybe a bit off, but who cares. */
	if (!force &&
	    clock == atomic_load_lax(&old_clock) &&
	    duration == atomic_load_lax(&old_duration))
		return;
	atomic_store_lax(&old_clock, clock);
	atomic_store_lax(&old_duration, duration);

	flockfile(tty);
	fprintf(tty, "%"PRId64"%c%c%c ",
			cur_number,
			has_number ? '?' : '\0',
			seek_cmd,
			atomic_load_lax(&paused) ? '.' : '>');

	fprintf(tty, "%3"PRId64":%02u / %3"PRId64":%02u (%3u%%)",
			clock / 60, (unsigned)(clock % 60),
			duration / 60, (unsigned)(duration % 60),
			duration ? (unsigned)(clock * 100 / duration) : 0);

	{
		unsigned k = atomic_load_lax(&cur_track) + 1,
		         n = atomic_load_lax(&in0.nb_audios);
		if (1 < (k | n))
			fprintf(tty, " Track: %d/%d", k, n);
	}

	{
		int v = atomic_load_lax(&volume);
		if (100 != v)
			fprintf(tty, " Vol: % 3d%%", v);
	}

	if (unlikely(AV_LOG_DEBUG <= av_log_get_level())) {
		uint16_t len = atomic_load_lax(&buffer_tail) - atomic_load_lax(&buffer_head);
		fprintf(tty, " buf:%"PRId64"kB low:%"PRId64"kB usr:%"PRId64"kB max:%"PRId64"kB pkt:%d",
				atomic_load_lax(&buffer_bytes) / 1024,
				atomic_load_lax(&buffer_full_bytes) / 2 / 1024,
				atomic_load_lax(&buffer_bytes_max) / 1024,
				len ? atomic_load_lax(&buffer_bytes) * (UINT16_MAX + 1) / len / 1024 : -1,
				len);
	}

	fputs(CR, tty);
	funlockfile(tty);
	progress_printed = 1;
}

static void
seek_player(int64_t ts, int whence)
{
	switch (whence) {
	case SEEK_SET:
		break;

	case SEEK_CUR:
	{
		int64_t base_pts = atomic_load_lax(&seek_pts);
		if (AV_NOPTS_VALUE == base_pts)
			base_pts = atomic_load_lax(&cur_pts);

		ts = base_pts + ts;
	}
		break;

	case SEEK_END:
		ts = atomic_load_lax(&cur_duration) + ts;
		break;

	default:
		abort();
	}

	if (ts < 0)
		ts = 0;

	atomic_store_lax(&seek_pts, ts);

	xassert(!pthread_mutex_lock(&buffer_lock));
	xassert(!pthread_cond_broadcast(&buffer_wakeup));
	xassert(!pthread_mutex_unlock(&buffer_lock));
}

static void
print_now_playing(void)
{
	char buf[20];
	strftime(buf, sizeof buf, "\e[1;33m%R> \e[m", localtime(&(time_t){ time(NULL) }));
	fputs(buf, tty);
}

static void
increment_xattr(Input *in, char const *xname, enum Metadata xm)
{
	if (!writable)
		return;

	xassert(!pthread_mutex_lock(&file_lock));
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
		goto out;
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
out:
	xassert(!pthread_mutex_unlock(&file_lock));
}

static void
print_format(void)
{
	fprintf(tty, "%s -> %s"LF,
			source_info.buf[birdlock_rd_acquire(&source_info.lock)],
			sink_info.buf[birdlock_rd_acquire(&sink_info.lock)]);
}

static void
print_around(PlaylistFile pf)
{
	PlaylistFile from = pf, to = pf;
	/* Hard limits to avoid wrap around. */
	PlaylistFile from_stop = seek_playlist(&master, NULL, 0, SEEK_SET),
	             to_stop = seek_playlist(&master, NULL, 0, SEEK_END);
	int height = (win_height - 1) * 3 / 8;
	/* Maximum number of visible lines in direction. */
	int from_lim = height * 3 / 8, to_lim = height - from_lim;

	int64_t from_offset = 0, to_offset = 0;

	/* Step in direction as much as possible. */
#define WALK(from, step) \
	while (0 < from##_lim && from.f != from##_stop.f) \
		from = seek_playlist(&master, &from, step, SEEK_CUR), \
		from##_offset += step, \
		--from##_lim;

	WALK(to, 1);
	from_lim += to_lim;
	WALK(from, -1);
	to_lim = height;

#undef WALK

	fprintf(tty, "\e[K\e[?7lPlaylist:\n");

	for (;;) {
		fprintf(tty, "\e[;%dm%6"PRIu64"\e[m ",
				from_offset ? 0 : 7,
				from_offset ? labs(from_offset) : get_file_index(from));

		print_file(from.f, tty);

		if (to_lim <= 0 || from.f == to_stop.f)
			break;
		from = seek_playlist(&master, &from, 1, SEEK_CUR);
		++from_offset;
		--to_lim;
	}

	fprintf(tty, "\e[?7h");
}

/* static void
finish_input(Input *in)
{} */

static int
seek_buffer(int64_t target_pts)
{
	int found = 0;

	uint16_t old_head = atomic_exchange_lax(&buffer_head, buffer_tail);

	int64_t dropped_bytes = 0;

	for (; old_head != buffer_tail /* := buffer_head but owned */; ++old_head) {
		AVFrame *frame = buffer[old_head];

		if (frame->best_effort_timestamp <= target_pts &&
		    target_pts < frame->best_effort_timestamp + frame->pkt_duration)
		{
			frame->opaque = (void *)(size_t)1;
			atomic_store_lax(&cur_pts, frame->pts);
			atomic_store_explicit(&buffer_head, old_head, memory_order_release);
			found = 1;
			break;
		}

		dropped_bytes += frame->pkt_size;
		av_frame_unref(frame);
	}

	xassert(dropped_bytes <= atomic_fetch_sub_lax(&buffer_bytes, dropped_bytes));

	return found;
}

static void
update_input_info(void)
{
	char *buf = source_info.buf[birdlock_wr_acquire(&source_info.lock)];
	int n = sizeof source_info.buf[0];

	print_stream(&buf, &n, &in0.s, 0);
	if (in0.cover_front) {
		AVCodecParameters *pars = in0.cover_front->codecpar;
		if (pars)
			sbprintf(&buf, &n, "; cover_front(%s), %dx%d",
					avcodec_get_name(pars->codec_id),
					pars->width, pars->height);
		else
			sbprintf(&buf, &n, "; cover_front(none)");
	}
	birdlock_wr_release(&source_info.lock);
}

static void *
source_worker(void *arg)
{
	(void)arg;

#if HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), "source");
#endif

	/* To avoid race condition, we must check all atomic conditions with
	 * acquired mutex lock before we would fall asleep. */
	int locked = 0;

	AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		print_error("Could not allocate memory");
		goto terminate;
	}

	int discont = 0;
	int sought = 0;

	buffer_full_bytes = buffer_bytes_max;

	for (;;) {
		int rc;

#if CONFIG_VALGRIND
		if (unlikely(atomic_load_lax(&terminate)))
			goto terminate;
#endif

		if (unlikely(atomic_load_lax(&seek_file0))) {
			xassert(!pthread_mutex_lock(&file_lock));
			/* Maybe deleted. */
			if (likely(seek_file0)) {
				if (!sought && 0 <= in0.fd) {
					unsigned percent = cur_duration ? atomic_load_lax(&cur_pts) * 100 / cur_duration : 0;
					if (percent < 20)
						/* Ignore. */;
					else if (percent < 80)
						increment_xattr(&in0, XATTR_SKIP_COUNT, M_skip_count);
					else
						increment_xattr(&in0, XATTR_PLAY_COUNT, M_play_count);
				}
				sought = 0;

				close_input(&in0);

				atomic_store_lax(&in0.pf.f, seek_file0);
				seek_file0 = NULL;
				in0.pf.p = get_parent(&master, &in0.pf.f->a);
				open_input(&in0);

				update_input_info();

				if (atomic_load_lax(&auto_w))
					print_around(in0.pf);
				if (atomic_load_lax(&auto_i))
					print_format();
				print_now_playing();
				print_file(in0.pf.f, tty);

				print_progress(1);
				if (tty)
					fflush(tty);

				update_cover(&in0);

				seek_buffer(INT64_MIN);
				atomic_store_lax(&seek_pts, seek_file_pts);

				discont = 0; /* TODO: Eh... seek by user =>flush or automatic =>no flush? */
			}
			xassert(!pthread_mutex_unlock(&file_lock));
		}

		int64_t target_pts = atomic_exchange_lax(&seek_pts, AV_NOPTS_VALUE);
		if (unlikely(AV_NOPTS_VALUE != target_pts && in0.s.codec_ctx)) {
			target_pts = av_rescale(target_pts,
					in0.s.audio->time_base.den,
					in0.s.audio->time_base.num);
			sought = 1;

			if (seek_buffer(target_pts)) {
				if (locked)
					goto wakeup_sink_locked;
				else
					goto wakeup_sink;
			}

			discont = 1;

			/* Maybe interesting: out.codec_ctx->delay. */

			avcodec_flush_buffers(in0.s.codec_ctx);
			if (avformat_seek_file(in0.s.format_ctx, in0.s.audio->index, 0, target_pts, target_pts, 0) < 0)
				av_log(in0.s.format_ctx, AV_LOG_ERROR, "Could not seek\n");
		}

		if (unlikely(!in0.s.codec_ctx) ||
		    unlikely(SS_STOPPED == source_state) ||
		    buffer_bytes_max <= atomic_load_explicit(&buffer_bytes, memory_order_acquire) ||
		    (unlikely(buffer_tail + 1 == atomic_load_lax(&buffer_head)) &&
		     (atomic_store_lax(&buffer_full_bytes, atomic_load_lax(&buffer_bytes)), 1)))
		{
			if (!locked) {
				atomic_store_lax(&source_state, SS_WAITING);

			wait:
				xassert(!pthread_mutex_lock(&buffer_lock));
				locked = 1;
				continue;
			}

			xassert(!pthread_cond_wait(&buffer_wakeup, &buffer_lock));
		}

		if (locked) {
			xassert(!pthread_mutex_unlock(&buffer_lock));
			locked = 0;
			continue;
		}

		AVFrame *frame = buffer[buffer_tail];

		if (!frame) {
			for (uint16_t to = atomic_load_lax(&buffer_head);
			     buffer_hair < to;
			     ++buffer_hair)
				if ((frame = buffer[buffer_hair])) {
					buffer[buffer_hair++] = NULL;
					break;
				}

			if (unlikely(!frame) &&
			    unlikely(!(frame = av_frame_alloc())))
			{
				print_error("Could not allocate memory");
				goto stop;
			}
			buffer[buffer_tail] = frame;
		}

		Input *in = &in0;

		rc = av_read_frame(in->s.format_ctx, pkt);
		if (unlikely(rc < 0)) {
			if (AVERROR_EOF != rc)
				av_log(in->s.format_ctx, AV_LOG_ERROR, "Could not read frame: %s\n",
						av_err2str(rc));

			if (SS_RUNNING != source_state &&
			    /* Buffer consumed. */
			    atomic_load_lax(&buffer_head) == atomic_load_lax(&buffer_tail))
				/* TODO: finish_input|in == in0 && next_cmd == in_next_cmd (g) => in = in1|emit next_cmd */
				/* Seek commands should fill next_in first. */
				write(control[1], (char const[]){ CONTROL('J') }, 1);

		stop:
			atomic_store_lax(&source_state, SS_STOPPED);
			goto wait;
		}

		/* Packet from an uninteresting stream. */
		if (unlikely(in->s.audio->index != pkt->stream_index)) {
			av_packet_unref(pkt);
			continue;
		}

		if (unlikely((AVSTREAM_EVENT_FLAG_METADATA_UPDATED & in->s.format_ctx->event_flags)) && tty) {
			in->s.format_ctx->event_flags &= ~AVSTREAM_EVENT_FLAG_METADATA_UPDATED;

			AVDictionaryEntry const *t = av_dict_get(in->s.format_ctx->metadata, "StreamTitle", NULL, 0);
			if (t) {
				print_now_playing();
				fprintf(tty, "[ICY] %s"LF, t->value);
				print_progress(1);
			}
		}

		/* Send read packet for decoding. */
		rc = avcodec_send_packet(in->s.codec_ctx, pkt);
		av_packet_unref(pkt);

		/* Receive decoded frame. */
		if (likely(0 <= rc))
			rc = avcodec_receive_frame(in->s.codec_ctx, frame);

		if (likely(0 <= rc)) {
			atomic_fetch_add_lax(&buffer_bytes, frame->pkt_size);

			/* Unused by FFmpeg. */
			frame->pts = av_rescale(frame->pts,
					in->s.audio->time_base.num,
					in->s.audio->time_base.den);
			frame->opaque = (void *)(size_t)discont;
			discont = 0;

			atomic_store_lax(&cur_duration,
					AV_NOPTS_VALUE == in0.s.format_ctx->duration
						? frame->pts
						: av_rescale(in0.s.format_ctx->duration, 1, AV_TIME_BASE));

			atomic_store_lax(&source_state, SS_RUNNING);

			int was_empty =
				atomic_load_lax(&buffer_head) ==
				atomic_fetch_add_explicit(&buffer_tail, 1, memory_order_release);
			if (unlikely(was_empty)) {
			wakeup_sink:
				xassert(!pthread_mutex_lock(&buffer_lock));
			wakeup_sink_locked:
				xassert(!pthread_cond_signal(&buffer_wakeup));
				xassert(!pthread_mutex_unlock(&buffer_lock));
			}

			print_progress(0);
			if (tty)
				fflush(tty);
		} else if (AVERROR(EAGAIN) != rc)
			av_log(in->s.format_ctx, AV_LOG_ERROR, "Could not decode frame: %s\n",
					av_err2str(rc));
	}

terminate:
	if (locked)
		xassert(!pthread_mutex_unlock(&buffer_lock));
	av_packet_free(&pkt);

	return NULL;
}

static void
flush_output(void)
{
	if (out.codec_ctx)
		avcodec_flush_buffers(out.codec_ctx);
	if (out.format_ctx)
		av_write_frame(out.format_ctx, NULL);
}

static void *
sink_worker(void *arg)
{
	(void)arg;

#if HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(pthread_self(), "sink");
#endif

	int locked = 0;
	AVFrame *frame = NULL;
	int64_t out_dts = 0;

	AVPacket *pkt = av_packet_alloc();
	AVBufferSrcParameters *pars = av_buffersrc_parameters_alloc();

	if (!pkt || !pars) {
		print_error("Could not allocate memory");
		goto terminate;
	}

	pars->time_base = (AVRational){ 1, 1 };

	for (;;) {
#if CONFIG_VALGRIND
		if (unlikely(atomic_load_lax(&terminate)))
			goto terminate;
#endif

		if (unlikely(atomic_load_lax(&paused))) {
			if (!locked)
				flush_output();
			goto wait;
		}

		uint16_t head = atomic_load_lax(&buffer_head);
		if (unlikely(head == atomic_load_explicit(&buffer_tail, memory_order_acquire)))
			goto wait;

		if (0) {
		wait:
			if (!locked) {
				xassert(!pthread_mutex_lock(&buffer_lock));
				locked = 1;
				continue;
			}
			xassert(!pthread_cond_wait(&buffer_wakeup, &buffer_lock));
		}

		if (locked) {
			xassert(!pthread_mutex_unlock(&buffer_lock));
			locked = 0;
			continue;
		}

		frame = atomic_exchange_lax(&buffer[head], frame);
		/* If head stayed the same we can be sure that picked frame is valid. */
		if (unlikely(!atomic_compare_exchange_strong_explicit(
				&buffer_head, &head, head + 1,
				memory_order_relaxed, memory_order_relaxed)))
			continue;

		int64_t rem_bytes = atomic_fetch_sub_lax(&buffer_bytes, frame->pkt_size) - frame->pkt_size;
		assert(0 <= rem_bytes);
		if ((rem_bytes <= atomic_load_lax(&buffer_full_bytes) / 2 &&
		     SS_WAITING == atomic_load_lax(&source_state)) ||
		    !rem_bytes)
		{
			if (AV_LOG_DEBUG <= av_log_get_level())
				fprintf(tty, "Requesting more bytes %ld %ld\n", rem_bytes , atomic_load_lax(&buffer_full_bytes) / 2);
			xassert(!pthread_mutex_lock(&buffer_lock));
			xassert(!pthread_cond_signal(&buffer_wakeup));
			xassert(!pthread_mutex_unlock(&buffer_lock));
		}

		int graph_changed = 0;
#define xmacro(x) (graph_changed |= pars->x != frame->x, pars->x = frame->x)
		xmacro(format);
		xmacro(sample_rate);
		xmacro(channel_layout);
#undef xmacro
		for (;;) {
			int rc = configure_output(frame);
			if ((!rc && unlikely(graph_changed)) ||
			    unlikely(0 < rc))
				rc = configure_graph(pars);
			if (likely(0 <= rc))
				break;

			print_error("Playback suspended");

			xassert(!pthread_mutex_lock(&buffer_lock));
#if CONFIG_VALGRIND
			if (unlikely(atomic_load_lax(&terminate))) {
				locked = 1;
				goto terminate;
			}
#endif
			xassert(!pthread_cond_wait(&buffer_wakeup, &buffer_lock));
			xassert(!pthread_mutex_unlock(&buffer_lock));
		}

		int desired_volume = atomic_load_lax(&volume);
		if (unlikely(graph_volume_volume != desired_volume)) {
			graph_volume_volume = desired_volume;

			char arg[50];
			snprintf(arg, sizeof arg, "%f",
					pow((desired_volume <= 0 ? 0 : desired_volume) / 100., M_E));
			if (avfilter_graph_send_command(graph, "volume", "volume", arg, NULL, 0, 0) < 0) {
				if (!avfilter_graph_get_filter(graph, "volume"))
					av_log(graph, AV_LOG_ERROR, "No 'volume' filter\n");
				av_log(graph, AV_LOG_ERROR, "Cannot set volume\n");
			}
		}

		if (unlikely(frame->opaque))
			flush_output();

		atomic_store_lax(&cur_pts, frame->pts);

		print_progress(0);
		if (tty)
			fflush(tty);

		frame->pts = out_dts;
		frame->pkt_dts = out_dts;
		frame->pkt_duration = frame->nb_samples *
			out.audio->time_base.den / frame->sample_rate / out.audio->time_base.num;

		int rc;

		rc = av_buffersrc_add_frame_flags(buffer_ctx, frame, AV_BUFFERSRC_FLAG_NO_CHECK_FORMAT);
		if (unlikely(rc < 0))
			av_log(graph, AV_LOG_ERROR,
					"Could not push frame into filtergraph: %s\n",
					av_err2str(rc));

		rc = av_buffersink_get_frame_flags(buffersink_ctx, frame, 0);
		if (unlikely(rc < 0))
			av_log(graph, AV_LOG_ERROR,
					"Could not pull frame from filtergraph: %s\n",
					av_err2str(rc));

		/* Send a frame to encode. */
		rc = avcodec_send_frame(out.codec_ctx, frame);
		if (unlikely(rc < 0))
			av_log(out.format_ctx, AV_LOG_ERROR,
					"Could not encode frame: %s\n",
					av_err2str(rc));

		av_frame_unref(frame);

		/* Receive an encoded packet. */
		while (0 <= (rc = avcodec_receive_packet(out.codec_ctx, pkt))) {
			out_dts += pkt->duration;

			rc = av_write_frame(out.format_ctx, pkt);
			if (unlikely(rc < 0))
				av_log(out.format_ctx, AV_LOG_ERROR,
						"Could not write encoded frame: %s\n",
						av_err2str(rc));
			av_packet_unref(pkt);
		}
		if (unlikely(AVERROR(EAGAIN) != rc))
			av_log(out.format_ctx, AV_LOG_ERROR,
					"Could not receive encoded frame: %s\n",
					av_err2str(rc));

		if (tty)
			fflush(tty);
	}

terminate:
	if (locked)
		xassert(!pthread_mutex_unlock(&buffer_lock));
	av_free(pars);
	av_frame_free(&frame);
	av_packet_free(&pkt);

	return NULL;
}

static void
save_master(void)
{
	save_playlist(&master);
}

static void
do_cleanup(void)
{
	fputs("Saving playlists..."CR, tty);
	fflush(tty);
	xassert(!pthread_mutex_lock(&file_lock));
	save_master();
	xassert(!pthread_mutex_unlock(&file_lock));

#if CONFIG_VALGRIND
	if (threads_inited) {
		atomic_store_lax(&terminate, 1);
		xassert(!pthread_mutex_lock(&buffer_lock));
		xassert(!pthread_cond_broadcast(&buffer_wakeup));
		xassert(!pthread_mutex_unlock(&buffer_lock));

		fputs("Waiting for producer thread to exit..."CR, tty);
		fflush(tty);
		xassert(!pthread_join(source_thread, NULL));

		fputs("Waiting for consumer thread to exit..."CR, tty);
		fflush(tty);
		xassert(!pthread_join(sink_thread, NULL));
	}

	fputs("Destroying locks..."CR, tty);
	fflush(tty);
	xassert(!pthread_mutex_destroy(&buffer_lock));
	xassert(!pthread_mutex_destroy(&file_lock));
	xassert(!pthread_cond_destroy(&buffer_wakeup));

	fputs("Releasing resources..."CR, tty);
	fflush(tty);
	cleanup_file(&master.a);

	close_input(&in0);
	close_output();
	close_graph();

	uint16_t i = 0;
	do
		av_frame_free(&buffer[i]);
	while ((uint16_t)++i);

	for (size_t i = 0; i < ARRAY_SIZE(search_history); ++i)
		free(search_history[i]);
#endif

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
play_file(File *f, int64_t pts)
{
	/* Mutex will acquire. */
	atomic_store_lax(&seek_file_pts, pts);
	atomic_store_lax(&seek_file0, f);

	xassert(!pthread_mutex_lock(&buffer_lock));
	xassert(!pthread_cond_broadcast(&buffer_wakeup));
	xassert(!pthread_mutex_unlock(&buffer_lock));
}

static void
handle_sigwinch(int sig)
{
	(void)sig;

	struct winsize w;
	win_height = !ioctl(fileno(tty), TIOCGWINSZ, &w) ? w.ws_row : 0;
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

static FILE *
open_tmpfile(char tmpname[PATH_MAX])
{
	char const *tmpdir = getenv("TMPDIR");
	snprintf(tmpname, PATH_MAX, "%s/muckXXXXXX",
			tmpdir ? tmpdir : "/tmp");
	int fd = mkostemp(tmpname, O_CLOEXEC);
	if (fd < 0) {
	fail:
		print_error("Failed to create temporary file: %s", strerror(errno));
		return NULL;
	}

	FILE *ret = fdopen(fd, "w");
	if (!ret)
		/* XXX: Does fd get closed? */
		goto fail;

	return ret;
}

static void
open_visual_search(void)
{
	char tmpname[PATH_MAX];
	FILE *stream = open_tmpfile(tmpname);
	if (!stream)
		return;

	int any = 0;
	for (size_t i = 0; i < ARRAY_SIZE(search_history) && search_history[i]; ++i) {
		fprintf(stream, "%s\n", search_history[i]);
		any = 1;
	}
	if (!any)
		fputc('\n', stream);
	fputc('\n', stream);

	PlaylistFile cur = get_current_pf();
	for (enum MetadataX m = 0; m < MX_NB; ++m) {
		char const *value = cur.f ? get_metadata(cur.p, cur.f, m) : NULL;
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
	char const *home = getenv("HOME");
	size_t home_size = strlen(home);
	int tilde = !strncmp(pathname, home, home_size);
	fprintf(stream, "# %s%s:\n", tilde ? "~" : "", pathname + (tilde ? home_size : 0));
	if (history) {
		char buf[BUFSIZ];
		size_t buf_size;
		while (0 < (buf_size = fread(buf, 1, sizeof buf, history)))
			fwrite(buf, 1, buf_size, stream);
		fclose(history);
	} else
		fprintf(stream, "# %s.\n", strerror(errno));
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
		char const *value = cur.f ? get_metadata(cur.p, cur.f, m) : NULL;
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
			"#\n"
			"# Favorite tracks:\n"
			"#   p=fav\n"
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

			char *carry = search_history[0];
			search_history[0] = NULL;
			for (size_t i = 1; i < ARRAY_SIZE(search_history) && carry; ++i) {
				if (!strcmp(carry, line)) {
					search_history[0] = carry;
					carry = NULL;
					break;
				}

				char *tmp = search_history[i];
				search_history[i] = carry;
				carry = tmp;
			}
			free(carry);

			if (!search_history[0])
				search_history[0] = line;
			else
				free(line);

			search_file(search_history[0]);
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

static unsigned char
toggle(atomic_uchar *obj, char const *msg)
{
	unsigned char yes = !atomic_fetch_xor_explicit(obj, 1, memory_order_relaxed);
	fprintf(tty, "%s: \e[%s\e[m"LF, msg, yes ? "1;32mYes" : "31mNo");
	return yes;
}

static void
pause_player(int pause)
{
	atomic_store_lax(&paused, pause);
	if (!pause) {
		xassert(!pthread_mutex_lock(&buffer_lock));
		xassert(!pthread_cond_broadcast(&buffer_wakeup));
		xassert(!pthread_mutex_unlock(&buffer_lock));
	}
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
	}

	if (CONTROL('J') == c)
		c = seek_cmd;

	PlaylistFile pf;
	switch (c) {
	case CONTROL('['):
		/* Noop. */
		break;

	case '*':
		atomic_store_lax(&volume, -volume);
		break;

	case '+':
		atomic_store_lax(&volume, FFMIN(volume + 1, 100));
		break;

	case '-':
		atomic_store_lax(&volume, FFMAX(volume - 2, 0));
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
		if (!toggle(&auto_i, "Auto i"))
			break;
		/* FALLTHROUGH */
	case 'i': /* Information. */
		print_format();
		print_file(atomic_load_lax(&in0.pf.f), tty);
		break;

	case 'm': /* Metadata. */
	{
		int rc = pthread_mutex_trylock(&file_lock);
		if (EBUSY == rc)
			break;
		xassert(!rc);
		int old_level = av_log_get_level();
		av_log_set_level(AV_LOG_DEBUG);
		av_dump_format(in0.s.format_ctx, 0, atomic_load_lax(&in0.pf.f)->a.url, 0);
		av_log_set_level(old_level);
		xassert(!pthread_mutex_unlock(&file_lock));
	}
		break;

	case '&':
	case '!':
		toggle(&live, "Live");
		break;

	case 't': /* Tracks. */
	{
		unsigned n = atomic_load_lax(&in0.nb_audios);
		if (n) {
			atomic_store_lax(&cur_track, (cur_track + 1) % n);
			play_file(atomic_load_lax(&in0.pf.f), atomic_load_lax(&cur_pts));
		} else {
			print_error("No audio tracks are found");
		}
	}
		break;

	case '/':
	case '=':
		open_visual_search();
		if (live) {
			PlaylistFile cur = get_current_pf();
			pf = seek_playlist(&master, &cur, 0, SEEK_CUR);
			if (pf.f != cur.f)
				goto play_file;
		}
		break;

	case '|':
		/* TODO: Plumb master playlist. */
	case 'e': /* Edit. */
	{
		if (live && 'e' == c) {
			seek_player(1, SEEK_CUR);
			break;
		}

		char tmpname[PATH_MAX];
		FILE *stream = open_tmpfile(tmpname);
		if (!stream)
			break;
		/* TODO: Edit currently playing playlist. Can be used
		 * to manually deselect files. Never touches real
		 * playlist. */
		xassert(!pthread_mutex_lock(&file_lock));
		plumb_file(&master.a, cur_filter[live], stream);
		xassert(!pthread_mutex_unlock(&file_lock));
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
	{
		seek_cmd = c;
		pf = seek_playlist(&master, NULL, POS_RND, SEEK_SET);
		goto play_file;
	}

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
		seek_cmd = c;
		pf = seek_playlist(&master, NULL, 'n' == c ? n_number : -n_number, SEEK_CUR);
	play_file:;
		play_file(pf.f, AV_NOPTS_VALUE);
	}
		break;

	case 'g': /* Go to. */
	{
		static int64_t g_number = 0;

		seek_cmd = c;
		use_number(&g_number);
		seek_player(g_number / 100 * 60 /* min */ + g_number % 100 /* sec */, SEEK_SET);
	}
		break;

	case 'G': /* GO TO. */
	{
		static int64_t G_number = 100 * 3 / 8;

		seek_player(atomic_load_lax(&cur_duration) * use_number(&G_number) / 100, SEEK_SET);
	}
		break;

	case 'h':
	case 'l':
		seek_player(('h' == c ? -1 : 1) * 5, SEEK_CUR);
		break;

	case 'j':
	case 'k':
		seek_player(('j' == c ? -1 : 1) * FFMAX(atomic_load_lax(&cur_duration) / 16, +5), SEEK_CUR);
		break;

	case 'W':
		if (!toggle(&auto_w, "Auto w"))
			break;
		/* FALLTHROUGH */
	case 'w': /* Where. */
		print_around(get_current_pf());
		break;

	case '.':
	case '>':
		pause_player('.' == c);
		break;

	case 'c': /* Continue. */
	case ' ':
		pause_player(!paused);
		break;

	case 'Z': /* Zzz. */
	case 'Q':
	case 'q':
		exit(EXIT_SUCCESS);

	case 'a': /* After. */
	case 'b': /* Before. */
		if (live && 'b' == c) {
			seek_player(-2, SEEK_CUR);
			break;
		}

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

		pf = get_current_pf();
		struct timespec mtim_before = get_file_mtim(pf);

		if (!spawn()) {
			Playlist *playlist = pf.p;
			File *f = pf.f;

			if (playlist &&
			    AT_FDCWD != playlist->dirfd &&
			    fchdir(playlist->dirfd) < 0)
			{
				print_error("Could not change working directory");
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
			print_error("No binding for '%c'", c);

			_exit(127);
		}

		struct timespec mtim_after = get_file_mtim(pf);

		if (memcmp(&mtim_before, &mtim_after, sizeof mtim_before)) {
			fprintf(tty, "Reloading changed file..."CR);
			fflush(tty);
			play_file(pf.f, atomic_load_lax(&cur_pts));
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
log_cb(void *ctx, int level, const char *format, va_list ap)
{
	(void)ctx;

	if (av_log_get_level() < level || !tty)
		return;

	if (progress_printed) {
		progress_printed = 0;
		fputs("\e[K", tty);
	}

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
#if 0
		pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL);
#endif

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
		print_error("Could not open control channel: %s", strerror(errno));

	/* Set defaults. */
	update_input_info();
	update_output_info();

	/* Setup ended, can load files now. */
	char const *startup_cmd = NULL;
	for (int c; 0 <= (c = getopt(argc, argv, "x:a:c:f:n:m:wd"));)
		switch (c) {
		case 'x':
			startup_cmd = optarg;
			break;

		case 'a':
			graph_descr = optarg;
			break;

		case 'c':
			ocodec = optarg;
			break;

		case 'f':
			oformat_name = optarg;
			break;

		case 'n':
			ofilename = optarg;
			break;

		case 'm':
			buffer_bytes_max = strtoll(optarg, NULL, 10) * 1024;
			break;

		case 'w':
			writable = 1;
			break;

		case 'd':
			av_log_set_level(av_log_get_level() < AV_LOG_DEBUG ? AV_LOG_DEBUG : AV_LOG_TRACE);
			break;

		default:
			exit(EXIT_FAILURE);
		}

	/* Spin up workers. */
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
			print_error("Could not create worker thread: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

#if CONFIG_VALGRIND
		threads_inited = 1;
#endif
	}

	/* Open arguments. */
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

	if (startup_cmd)
		do_cmd_str(startup_cmd);
	else
		play_file(seek_playlist(&master, NULL, 0, SEEK_SET).f, AV_NOPTS_VALUE);

	/* TUI event loop. */
	{
		struct pollfd fds[2];
		/* Either read user input... */
		fds[0].fd = fileno(tty);
		fds[0].events = POLLIN;

		/* ...or the internal channel, used to auto play next track. */
		fds[1].fd = control[0];
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
