#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <ncurses.h>
#include <poll.h>
#include <pthread.h>
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

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
_Static_assert(8 == CHAR_BIT);

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

#if !HAVE_PTHREAD_SETNAME_NP
# define pthread_setname_np(...) (void)0
#endif

#if !HAVE_STRCHRNUL
static char *
strchrnul(char const *s, char c)
{
	char *ret = strchr(s, c);
	return ret ? ret : s + strlen(s);
}
#endif

#define FFMINMAX(min, x, max) FFMAX(min, FFMIN(x, max))

#define ARRAY_SIZE(x) (sizeof x / sizeof *x)

#define PTR_INC(pp, n) (pp) = (void *)((char *)(pp) + (n))

#define CONTROL(c) ((c) - '@')

enum {
	KEY_FOCUS_IN = 1001,
	KEY_FOCUS_OUT = 1002,
};
static char const SEND_FOCUS_EVENTS[] = "\033[?1004h";
static char const STOP_FOCUS_EVENTS[] = "\033[?1004l";

#define atomic_exchange_lax(...) atomic_exchange_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_add_lax(...) atomic_fetch_add_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_or_lax(...) atomic_fetch_or_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_fetch_sub_lax(...) atomic_fetch_sub_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_load_lax(...) atomic_load_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_store_lax(...) atomic_store_explicit(__VA_ARGS__, memory_order_relaxed)

#define IS_SUFFIX(haystack, needle) \
	(strlen(needle) <= haystack##_size && \
	 !memcmp(haystack + haystack##_size - strlen(needle), needle, strlen(needle)) && \
	 (haystack##_size -= strlen(needle), 1))

#define ALIGNED_ATOMIC _Alignas(64)

#define COMPRESSORS \
	/* xmacro(ext, program) */ \
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
	/* xmacro(letter, name, def_width, in_url) */ \
	/* Contributors first. */ \
	xmacro('a', artist, 20, 1) \
	xmacro('A', album_artist, 25, 1) \
	xmacro('F', album_featured_artist, 15, 1) \
	xmacro('f', featured_artist, 15, 1) \
	xmacro('x', remixer, 15, 1) \
	/* Let barcode be the first album related metadata, since same named \
	 * albums (with matching album related metadata) can appear from \
	 * different contributors. This way remaining metadata stays highly \
	 * compressable even if barcode is different. */ \
	xmacro('B', barcode, 13, 0) \
	/* Wrap album title between disc/track totals. */ \
	xmacro('d', disc, 2, 1) \
	xmacro('D', disc_total, 2, 0) \
	xmacro('T', album, 25, 1) \
	xmacro('V', album_version, 15, 1) \
	xmacro('N', track_total, 2, 0) \
	xmacro('n', track, 2, 1) \
	/* Similer titles have higher chance to have the same ISRC. */ \
	xmacro('I', isrc, 12, 0) \
	xmacro('t', title, 20, 1) \
	xmacro('v', version, 20, 1) \
	/* Keep genre around bpm. */ \
	xmacro('g', genre, 35, 0) \
	/* A label used to release in a few genres with near constant bpm. */ \
	xmacro('b', bpm, 3, 0) \
	xmacro('L', label, 30, 1) \
	/* Catalog numbers has an alpha prefix that relates to label. Let's put it \
	 * after label. */ \
	xmacro('C', catalog, 15, 0) \
	xmacro('y', date, 10, 0) \
	xmacro('o', codec, 18, 0) \
	xmacro('m', mtime, 10, 0) \
	xmacro('l', length, 6, 0) \
	xmacro('z', comment, 20, 0)

/* Extra metadata-like stuff. */
#define METADATAX \
	xmacro('i', index, 0, 0) \
	xmacro('u', name, 30, 1) \
	xmacro('U', url, 50, 1) \
	xmacro('p', playlist, 15, 0)

#define METADATA_ALL METADATA METADATAX

static char const METADATA_LETTERS[] = {
#define xmacro(letter, name, ...) letter,
	METADATA_ALL
#undef xmacro
};

static char const METADATA_NAMES[][24] = {
#define xmacro(letter, name, ...) #name,
	METADATA_ALL
#undef xmacro
};

static uint8_t const METADATA_COLUMN_WIDTHS[] = {
#define xmacro(letter, name, def_width, ...) def_width,
	METADATA_ALL
#undef xmacro
};

enum Metadata {
#define xmacro(letter, name, ...) M_##name,
	METADATA
#undef xmacro
	M_NB,
};

enum MetadataX {
	MX_ = M_NB - 1,
#define xmacro(letter, name, ...) MX_##name,
	METADATAX
#undef xmacro
	MX_NB,
};

/* May present in URL if not among tags. */
static uint64_t const METADATA_IN_URL =
#define xmacro(letter, name, def_width, in_url) +(UINT64_C(in_url) << M_##name)
	METADATA
#undef xmacro
#define xmacro(letter, name, def_width, in_url) +(UINT64_C(in_url) << MX_##name)
	METADATAX
#undef xmacro
	;

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

enum ExprType {
	T_NEG,
	T_AND,
	T_OR,
	T_KV,
};

enum KeyOp {
	OP_RE = 1 << 0,
	OP_LT = 1 << 1,
	OP_EQ = 1 << 2,
	OP_GT = 1 << 3,
	OP_ISSET = 1 << 4,
};

/* NOTE: ZARY (NULL) is a special 0-ary expression that always evalutes to
 * true. */

typedef struct Expr Expr;
struct Expr {
	enum ExprType type;
	union {
		/* Unary operator. */
		struct {
			Expr *expr;
		} un;

		/* Binary operator. */
		struct {
			Expr *lhs;
			Expr *rhs;
		} bi;

		/* Key-value expression. */
		struct {
			uint64_t keys;
			enum KeyOp op;
			union {
				pcre2_code *re;
				struct {
					uint8_t nnums;
					uint64_t nums[5];
				};
			};
		} kv;
	};
};

typedef struct {
	char const *ptr;
	char error_buf[256];
	char const *error_msg;
	PlaylistFile cur;
	pcre2_match_data *match_data;
} ExprParserContext;

typedef struct {
	PlaylistFile pf;
	pcre2_match_data *match_data;
} ExprEvalContext;

typedef struct {
	Expr *query;
	uint8_t filter_index;
} MatchFileContext;

typedef struct {
	MatchFileContext ctx;
	pcre2_match_data *match_data;
} MatchFileWorkerContext;

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

typedef struct FileTask FileTask;

typedef struct {
	FileTask *task;
	PlaylistFile cur;
	size_t count;
	pthread_t thread;
	void const *arg;
} FileTaskWorker;

struct FileTask {
	pthread_mutex_t mutex;
	PlaylistFile cur;
	int64_t remaining;
	int64_t batch_size;
	uint8_t nworkers;
	int (*routine)(FileTaskWorker *, void const *);
	FileTaskWorker workers[64];
};

static pthread_t main_thread;
static pthread_t source_thread, sink_thread;
static int wakeup_source, wakeup_sink;
#if CONFIG_VALGRIND
static int threads_inited;
static atomic_uchar ALIGNED_ATOMIC terminate;
#endif

static char const *ocodec = "pcm";
static char const *oformat_name = "alsa";
static char const *ofilename = NULL;

static Input in0 = INPUT_INITIALIZER;
static Stream out;
static unsigned _Atomic cur_track;
static atomic_uchar ALIGNED_ATOMIC dump_in0;
static PlaylistFile top;
static File *sel;

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
static int64_t _Atomic buffer_low; /**< When to wake up producer for more frames. */

/**
 * Producer buffer.
 *
 * Making it non-resizable simplifies implementation.
 */
static AVFrame *buffer[UINT16_MAX + 1];
static uint16_t _Atomic ALIGNED_ATOMIC buffer_head, buffer_tail;
/**
 * buffer_reap..buffer_head: Maybe alloced, reusable frames.
 * buffer_tail..buffer_reap: NULLs.
 */
static uint16_t buffer_reap;

static int64_t _Atomic ALIGNED_ATOMIC cur_pts, cur_duration;
static int64_t notify_pts, notify_duration;
static atomic_uchar ALIGNED_ATOMIC paused;

static pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;
static Playlist master;

static uint8_t cur_filter[2]; /**< .[live] is the currently used filter. */
/* TODO: Queue is live queue has p=^queue$ filter. In non-live mode we can select tracks etc. */
static int live = 1;

static char *search_history[10];

static char seek_cmd = 'n';
static RndState rnd;
static File *seek_file0;
static int64_t _Atomic seek_file_pts = AV_NOPTS_VALUE;
static int64_t _Atomic seek_pts = AV_NOPTS_VALUE;

static char const *column_spec = "iy30a,x25A+Fd*20Tn*40t+f+vlgbIB*LCom*z";

static char number_cmd[2];
static int64_t cur_number[2];
static int sel_y, sel_x;
static int scroll_x;
static int widen;

static FILE *tty, *fmsg;
static char msg_path[PATH_MAX];
static atomic_uchar ALIGNED_ATOMIC focused = 1;

static char config_home[PATH_MAX];
static char cover_path[PATH_MAX];

static pcre2_code *re_ucase;

enum Event {
	EVENT_FILE_CHANGED = 1 << 0,
	EVENT_STATE_CHANGED = 1 << 1,
	EVENT_EOF_REACHED = 1 << 2,
};

static atomic_uchar ALIGNED_ATOMIC pending_events;

static void
notify_event(enum Event event)
{
	if (!atomic_fetch_or_lax(&pending_events, event))
		pthread_kill(main_thread, SIGRTMIN);
}

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
	flockfile(fmsg);
	fputs("\033[1;31m", fmsg);
	vfprintf(fmsg, msg, ap);
	fputs("\033[m\n", fmsg);
	funlockfile(fmsg);
	va_end(ap);
}

static void
print_strerror(char const *msg)
{
	print_error("%s: %s", msg, strerror(errno));
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
print_averror(char const *msg, int err)
{
	print_error("%s: %s", msg, av_err2str(err));
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

#define xmacro(ext, program) || IS_SUFFIX(url, ext)
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

#define xmacro(ext, program) if (IS_SUFFIX(url, ext)) return program;
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

		for (enum Metadata i = 0; i < M_NB; ++i) {
			fputc('\t', stream);
			if (f->metadata[i])
				fputs(f->a.url + f->metadata[i], stream);
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
	for (enum Metadata i = 0; i < M_NB; ++i) {
		fputc('\t', stream);
		fputs(METADATA_NAMES[i], stream);
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
			print_file_strerror(parent->parent, &parent->a,
					"Could not append file to playlist");
			exit(EXIT_FAILURE);
		}
		void *old_files = parent->files;
		parent->files = p;

		/* Update parent references. */
		if (old_files != parent->files)
			for_each_playlist(child_playlist, parent)
				for_each_playlist(grandchild_playlist, child_playlist)
					PTR_INC(grandchild_playlist->parent,
							(char *)parent->files - (char *)old_files);
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
	fprintf(fmsg, "\033[1;%dm", color);
	fputs(get_playlist_name(playlist), fmsg);
	fputs(":", fmsg);
	if (lnum) {
		fprintf(fmsg, "%zu:", lnum);
		if (col)
			fprintf(fmsg, "%zu:", col);
	}
	fprintf(fmsg, " %s\033[m\n", msg);
}

static void
read_file(Playlist *parent, AnyFile *a);

static void
read_playlist(Playlist *playlist, int fd)
{
	char const *error_msg = NULL;

	File file;

	char fdata[UINT16_MAX];
	size_t fdata_size;
#define RESET_FDATA \
	for (enum Metadata i = 0; i < M_NB; ++i) \
		file.metadata[i] = UINT16_MAX; \
	fdata_size = 0;

	char buf[UINT16_MAX];
	uint16_t buf_size = 0;
	char *line = buf;

	int is_m3u = 0;

	size_t lnum = 1;
	char *col;

	RESET_FDATA;

	for (;;) {
		col = NULL;

		char *line_end;
		while (!(line_end = memchr(line, '\n', buf_size))) {
			if (sizeof buf - 1 == buf_size) {
				error_msg = "Too long line";
				goto out;
			}

			memmove(buf, line, buf_size);
			line = buf;

			ssize_t len = read(fd, buf + buf_size, (sizeof buf - 1) - buf_size);
			if (len < 0) {
				error_msg = "Could not read playlist stream";
				goto out;
			} else if (!len) {
				if (!buf_size)
					goto out;

				line_end = buf + buf_size;
				++buf_size;
				break;
			}

			buf_size += len;
		}

		*line_end = '\0';

		if (1 == lnum && !strcmp(line, "#EXTM3U")) {
			is_m3u = 1;
		} else if (is_m3u && '#' == *line) {
#define IS_DIRECTIVE(directive) \
	(!memcmp(line + 1, directive, strlen(directive)) && \
	 (col = line + 1 + strlen(directive)))

			if (IS_DIRECTIVE("EXTINF:")) {
				RESET_FDATA;

				file.metadata[M_length] = 0;
				while ('0' <= *col && *col <= '9') {
					if (sizeof fdata - 1 < fdata_size) {
					fail_too_long:
						error_msg = "Too much data";
						goto out;
					}
					fdata[fdata_size++] = *col++;
				}
				fdata[fdata_size++] = '\0';

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
					case M_length:
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

					file.metadata[m] = fdata_size;
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

						if (sizeof fdata - 1 < fdata_size)
							goto fail_too_long;
						fdata[fdata_size++] = *col++;
					}
					fdata[fdata_size++] = '\0';
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

			if (sizeof fdata < url_size + fdata_size)
				goto fail_too_long;

			enum FileType type = probe_url(NULL, url);
			AnyFile *a = append_file(playlist, type);
			if (a->type <= F_FILE) {
				File *f = (void *)a;
				for (enum Metadata i = 0; i < M_NB; ++i)
					f->metadata[i] = UINT16_MAX != file.metadata[i]
						? url_size + file.metadata[i]
						: 0;
			} else {
				fdata_size = 0;
			}

			if (!(a->url = malloc(url_size + fdata_size)))
				goto fail_enomem;
			memcpy(a->url, url, url_size);
			memcpy(a->url + url_size, fdata, fdata_size);

			read_file(playlist, a);
			RESET_FDATA;
		}

		++line_end; /* Skip LF. */
		buf_size -= line_end - line;
		line = line_end;
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

#undef RESET_FDATA
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
reap(pid_t pid, char const *program)
{
	int status;
	xassert(0 <= waitpid(pid, &status, 0));

	if (!(WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status)))
		print_error("Program %s terminated with failure", program);
}

static void
compress_playlist(Playlist *playlist, int *pfd, pid_t *pid, char const **program, int do_compress)
{
	int pipes[2] = { -1, -1 };

	*program = probe_compressor(playlist->a.url);

	pipe2(pipes, O_CLOEXEC);

	if ((*pid = fork()) < 0) {
		print_file_strerror(playlist->parent, &playlist->a,
				do_compress
					? "Could not compress playlist"
					: "Could not decompress playlist");
	} else if (!*pid) {
		if (dup2(do_compress ? pipes[0] : *pfd, STDIN_FILENO) < 0 ||
		    dup2(do_compress ? *pfd : pipes[1], STDOUT_FILENO) < 0 ||
		    execlp(*program, *program, "-c", do_compress ? NULL : "-d", NULL) < 0)
			print_file_strerror(playlist->parent, &playlist->a,
					do_compress
						? "Could not compress playlist"
						: "Could not decompress playlist");
		_exit(EXIT_FAILURE);
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
		pid_t pid = -1;
		char const *program;

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
write_file(File const *f, FILE *stream)
{
	int any = 0;
	for (enum Metadata i = 0; i < M_NB; ++i) {
		if (!f->metadata[i])
			continue;
		if (M_length == i)
			continue;

		if (!any)
			fprintf(stream, "#EXTINF:%s",
					f->metadata[M_length]
						? f->a.url + f->metadata[M_length]
						: "");

		fprintf(stream, " %s=\"", METADATA_NAMES[i]);
		for (char const *c = f->a.url + f->metadata[i]; *c; ++c) {
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

static void
write_playlist(Playlist *playlist, FILE *stream)
{
	fprintf(stream, "#EXTM3U\n");
	if (playlist->name)
		fprintf(stream, "#PLAYLIST:%s\n", playlist->name);

	for_each_file() {
		if (a->type <= F_FILE)
			write_file((File *)a, stream);
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

	fprintf(fmsg, "Saving %s...\n", playlist->a.url);

	char tmp[PATH_MAX];

	int n = snprintf(tmp, sizeof tmp,
			"%s~", playlist->a.url);
	if ((int)sizeof tmp <= n)
		goto fail_open;

	int dirfd = playlist->parent ? playlist->parent->dirfd : AT_FDCWD;
	int fd = openat(dirfd, tmp, O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (fd < 0) {
	fail_open:
		print_file_strerror(playlist->parent, &playlist->a,
				"Could not open temporary file");
		return;
	}

	pid_t pid = -1;
	char const *program;

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
		unlink(tmp);
		return;
	}
	fclose(stream);

	if (0 <= pid)
		reap(pid, program);

	if (renameat(dirfd, tmp, dirfd, playlist->a.url) < 0) {
		unlink(tmp);
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
			print_averror("Could not close output", rc);
	}

	if (out.codec_ctx)
		avcodec_free_context(&out.codec_ctx);
	if (out.format_ctx) {
		avio_closep(&out.format_ctx->pb);
		avformat_free_context(out.format_ctx);
		out.format_ctx = NULL;
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
fdata_write_date(File *tmpf, char *fdata, size_t *fdata_size, enum Metadata m, time_t time)
{
	size_t size = UINT16_MAX - *fdata_size;
	int n = strftime(fdata + *fdata_size, size, "%F", gmtime(&time));
	if (!n)
		return -1;

	tmpf->metadata[m] = *fdata_size;
	fdata[*fdata_size + n] = '\0';
	*fdata_size += n + 1 /* NUL */;

	return 0;
}

static int
fdata_writef(File *tmpf, char *fdata, size_t *fdata_size, enum Metadata m, char const *format, ...)
{
	va_list ap;

	va_start(ap, format);
	size_t size = UINT16_MAX - *fdata_size;
	int n = vsnprintf(fdata + *fdata_size, size, format, ap);
	va_end(ap);

	if (size <= (size_t)n)
		return -1;
	if (!n)
		return 0;

	tmpf->metadata[m] = *fdata_size;
	fdata[*fdata_size + n] = '\0';
	*fdata_size += n + 1 /* NUL */;

	return 0;
}

static int
fdata_write(File *tmpf, char *fdata, size_t *fdata_size, enum Metadata m, char const *value)
{
	size_t old_fdata_size = *fdata_size;
	int any = !!tmpf->metadata[m];

	if (!any) {
		tmpf->metadata[m] = *fdata_size;
	} else {
		switch (m) {
		case M_track:
		case M_disc:
			/* Multiplicity is not supported because fdata was may
			 * be interrupted with M_*_total part. */
			return 0;

		default:
			fdata[*fdata_size - 1] = ';';
			break;
		}
	}

	char pc = '\0';
	for (;; ++value) {
		if (UINT16_MAX <= *fdata_size)
			return -1;
		if (!*value)
			break;
		char c = (unsigned char)*value < ' ' ? ' ' : *value;
		switch (m) {
		default:
			/* Nothing. */
			break;

		case M_track:
		case M_disc:
			if ('/' == c)
				goto eos;
			/* FALLTHROUGH */
		case M_track_total:
		case M_disc_total:
		case M_date:
		case M_bpm:
			/* Trim leading zeros. */
			if (!pc && '0' == c)
				continue;
		}
		if ((!pc || ' ' == pc) && ' ' == c)
			continue;
		fdata[(*fdata_size)++] = c;
		pc = c;
	}
eos:
	*fdata_size -= ' ' == pc;
	if (old_fdata_size == *fdata_size) {
	rollback:
		if (!any)
			tmpf->metadata[m] = 0;
		else
			fdata[old_fdata_size] = '\0';
		return 0;
	}
	fdata[(*fdata_size)++] = '\0';

	if (M_date == m &&
	    *fdata_size - old_fdata_size == 8 + 1 /* NUL */)
	{
		if (UINT16_MAX <= *fdata_size + 2)
			return -1;

		/*-    543210
		 * 11112233Z
		 * 1111-22-33Z
		 *          ^*/
		memmove(&fdata[*fdata_size - 1], &fdata[*fdata_size - 3], 3);
		memmove(&fdata[*fdata_size - 4], &fdata[*fdata_size - 5], 2);
		fdata[*fdata_size - 2] = '-';
		fdata[*fdata_size - 5] = '-';
		*fdata_size += 2;
	}

	/* Use most precise date. */
	if (M_date == m && any) {
		if (old_fdata_size - tmpf->metadata[m] < *fdata_size - old_fdata_size) {
			memmove(&fdata[tmpf->metadata[m]],
					&fdata[old_fdata_size],
					*fdata_size - old_fdata_size);
			*fdata_size = old_fdata_size;
		} else {
			goto rollback;
		}
	}

	if (*value) {
		assert(M_track == m || M_disc == m);
		assert('/' == *value);
		enum Metadata totalm = M_disc == m
			? M_disc_total
			: M_track_total;
		return fdata_write(tmpf, fdata, fdata_size, totalm, value + 1);
	}

	return 0;
}

static void
read_metadata(Input const *in)
{
	typedef struct {
		enum Metadata m;
		char const *tags;
	} MetadataMapEntry;

	static MetadataMapEntry const METADATA_MAP[] = {

		{ M_album, "album\0" },
		{ M_album_artist, "album_artist\0" },
		{ M_album_featured_artist, "ALBUM/FEATURED_ARTIST\0" },
		{ M_album_version, "album_version\0" "ALBUM/VERSION\0" },
		{ M_artist, "artist\0" "ARTISTS\0" },
		{ M_barcode, "ALBUM/BARCODE\0" "BARCODE\0" "UPC\0" "EAN\0" },
		{ M_bpm, "TBPM\0" },
		{ M_catalog, "ALBUM/CATALOG_NUMBER\0" },
		{ M_date, "ALBUM/DATE_RELEASED\0" "date_released\0" "date\0" "date_published\0" "TYER\0" },
		{ M_disc, "disc\0" },
		{ M_disc_total, "disc_total\0" },
		{ M_featured_artist, "TRACK/FEATURED_ARTIST\0" },
		{ M_genre, "genre\0" },
		{ M_isrc, "TRACK/ISRC" "isrc\0" "TSRC\0" },
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
	char fdata[UINT16_MAX];

	/* Begin file data with its URL. */
	size_t url_size = strlen(f->a.url) + 1 /* NUL */;
	size_t fdata_size = url_size;

	for (enum Metadata i = 0; i < M_NB; ++i)
		tmpf.metadata[i] = 0;

	{
		/* Append duration. */
		int64_t duration = in->s.format_ctx->duration;
		if (AV_NOPTS_VALUE != duration) {
			int rc = fdata_writef(&tmpf, fdata, &fdata_size, M_length,
					"%"PRId64,
					av_rescale(duration, 1, AV_TIME_BASE));
			if (rc < 0)
				goto fail_too_long;
		}
	}

	{
		struct stat st;
		if (0 <= in->fd && 0 <= fstat(in->fd, &st) &&
		    fdata_write_date(&tmpf, fdata, &fdata_size, M_mtime, st.st_mtime) < 0)
			goto fail_too_long;
	}

	for (MetadataMapEntry const *e = METADATA_MAP;
	     e < (&METADATA_MAP)[1];
	     ++e)
		for (char const *key = e->tags;
		     *key;
		     key += strlen(key) + 1 /* NUL */)
		{
			for (AVDictionaryEntry const *t = NULL;
			     (t = av_dict_get(m, key, t, 0));)
				if (fdata_write(&tmpf, fdata, &fdata_size, e->m, t->value) < 0)
					goto fail_too_long;

			if (tmpf.metadata[e->m])
				break;
		}

	{
		char buf[128];
		av_get_channel_layout_string(buf, sizeof buf,
				in->s.codec_ctx->channels,
				in->s.codec_ctx->channel_layout);
		int rc = fdata_writef(&tmpf, fdata, &fdata_size, M_codec,
				"%s-%s-%d",
				in->s.codec_ctx->codec->name,
				buf,
				in->s.codec_ctx->sample_rate / 1000);
		if (rc < 0)
			goto fail_too_long;
	}

	/* Preserve. */
	if (f->metadata[M_comment]) {
		int rc = fdata_writef(&tmpf, fdata, &fdata_size, M_comment,
				"%s", f->a.url + f->metadata[M_comment]);
		if (rc < 0)
			goto fail_too_long;
	}

	if (!playlist->modified) {
		for (enum Metadata i = 0; i < M_NB; ++i)
			if (!!tmpf.metadata[i] != !!f->metadata[i] ||
			    (tmpf.metadata[i] &&
			     strcmp(fdata + tmpf.metadata[i], f->a.url + f->metadata[i])))
				goto changed;
		return;
	changed:
	}

	void *p = malloc(fdata_size);
	if (!p) {
		print_error("Could not allocate memory");
		return;
	}

	playlist->modified = 1;

	memcpy(p, f->a.url, url_size);
	memcpy(p + url_size, fdata + url_size, fdata_size - url_size);

	free(f->a.url);
	f->a.url = p;

	memcpy(f->metadata, tmpf.metadata, sizeof tmpf.metadata);

	return;

fail_too_long:
	print_file_error(playlist, &f->a, "Too much metadata", NULL);
}

static void
update_cover(Input const *in)
{
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof tmp, "%s~", cover_path);

	int fd = open(tmp, O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IRGRP);
	if (fd < 0)
		return;

	uint8_t const *data;
	int data_size = 0;

	AVStream const *stream = in->cover_front;
	if (stream) {
		AVPacket const *pic = &stream->attached_pic;
		data = pic->data;
		data_size = pic->size;
	}

	if (data_size <= 0) {
		static uint8_t const DEFAULT_COVER[] =
		{
#include "cover.png.h"
		};

		data = DEFAULT_COVER;
		data_size = sizeof DEFAULT_COVER;
	}

	(void)write(fd, data, data_size);
	if (close(fd))
		print_strerror("Could not write cover");
	else if (rename(tmp, cover_path))
		print_strerror("Could not rename cover");
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
		print_file_averror(playlist, &f->a, "Could not open input", rc);
		return;
	}

	/* Get information on the input file (number of streams etc.). */
	(void)avformat_find_stream_info(in->s.format_ctx, NULL);

	in->cover_front = NULL;
	in->s.audio = NULL;

	unsigned nb_audios = 0;
	unsigned track = atomic_load_lax(&cur_track);

	for (unsigned i = 0; i < in->s.format_ctx->nb_streams; ++i) {
		AVStream *stream = in->s.format_ctx->streams[i];

		stream->discard = AVDISCARD_ALL;

		if (AVMEDIA_TYPE_AUDIO == stream->codecpar->codec_type) {
			if (!track || track == nb_audios)
				in->s.audio = stream;
			++nb_audios;
			continue;
		}

		if ((AV_DISPOSITION_ATTACHED_PIC & stream->disposition) &&
		    AVMEDIA_TYPE_VIDEO == stream->codecpar->codec_type)
		{
			AVDictionaryEntry const *title;
			title = av_dict_get(stream->metadata, "comment", NULL, 0);
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

	if (track < nb_audios)
		atomic_store_lax(&cur_track, 0);
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
		av_get_channel_layout_string(*pbuf, *pn,
				s->codec_ctx->channels,
				s->codec_ctx->channel_layout);
		int k = strlen(*pbuf);
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

	if (!(buffer_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("abuffer"), "src")) ||
	    !(format_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("aformat"), "aformat")) ||
	    !(buffersink_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("abuffersink"), "sink")))
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
		error_msg = "Could not initialize filters";
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

	rc = avfilter_link(sink_end->filter_ctx, 0, buffersink_ctx, 0);
	if (rc < 0) {
		error_msg = "Could not create link";
		goto out;
	}

	rc = avfilter_graph_parse_ptr(graph, graph_descr,
			&sink_end, &src_end, NULL);
	if (rc < 0) {
		error_msg = "Could not parse filtergraph";
		goto out;
	}

	if ((rc = avfilter_graph_config(graph, NULL)) < 0) {
		error_msg = "Could not configure filtergraph";
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
		print_error("Could not find encoder");
		goto fail;
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

	rc = avformat_alloc_output_context2(&out.format_ctx, NULL,
			oformat_name, ofilename);
	if (rc < 0) {
		print_averror("Could not allocate output", rc);
		goto fail;
	}

	if (!(AVFMT_NOFILE & out.format_ctx->oformat->flags)) {
		rc = avio_open(&out.format_ctx->pb, ofilename, AVIO_FLAG_WRITE);
		if (rc < 0) {
			print_averror("Could not open output filename", rc);
			goto fail;
		}
	}

	AVStream *stream;
	/* Create a new audio stream in the output file container. */
	if (!(stream = avformat_new_stream(out.format_ctx, NULL))) {
		print_averror("Could not allocate output stream", rc);
		goto fail;
	}

	if (!(out.codec_ctx = avcodec_alloc_context3(codec))) {
		print_averror("Could not allocate encoder", rc);
		goto fail;
	}

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

	if ((rc = avcodec_open2(out.codec_ctx, codec, NULL)) < 0 ||
	    (rc = avcodec_parameters_from_context(stream->codecpar, out.codec_ctx)) < 0)
	{
		print_averror("Could not open encoder", rc);
		goto fail;
	}

	rc = avformat_write_header(out.format_ctx, NULL);
	if (rc < 0) {
		print_averror("Could not open output", rc);
		goto fail;
	}

	out.audio = out.format_ctx->streams[0];

	update_output_info();

	return 1;

fail:
	close_output();
	return -1;
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

			ret += (File *)playlist - (File *)child;
			ret += playlist->child_filter_count[0];
			child = (void *)((char *)playlist + get_file_size(F_PLAYLIST));
		}

		ret += (File *)a - (File *)child;
	}

	return ret;
}

static Playlist *
get_parent(Playlist const *ancestor, AnyFile const *a)
{
	if ((uintptr_t)a - (uintptr_t)ancestor->files < ancestor->files_size)
		return (Playlist *)ancestor;

	for_each_playlist(child, ancestor) {
		Playlist *ret = get_parent(child, a);
		if (ret)
			return ret;
	}

	return NULL;
}

enum { FILE_METADATA_BUFSZ = 20, };

static char const *
get_metadata(Playlist const *playlist, File const *f, enum MetadataX m,
		char buf[FILE_METADATA_BUFSZ])
{
	if (m < (enum MetadataX)M_NB)
		return f->metadata[m] ? f->a.url + f->metadata[m] : NULL;
	else switch (m) {
	case MX_index:
		sprintf(buf, "%"PRIu64, get_file_index((PlaylistFile){
			(Playlist *)playlist, (File *)f
		}));
		return buf;

	case MX_url:
		return f->a.url;

	case MX_name:
	{
		char const *p = strrchr(f->a.url, '/');
		return p && p[1] ? p + 1 : f->a.url;
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

static char const *
expr_strtou64(char const *s, uint64_t *ret)
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

static int
expr_eval_kv_key(Expr const *expr, enum MetadataX m, ExprEvalContext const *ctx)
{
	char mbuf[FILE_METADATA_BUFSZ];
	char const *value = get_metadata(ctx->pf.p, ctx->pf.f, m, mbuf);

	/* Fallback to the URL if metadata is missing for this
	 * file. This way user can avoid nasty queries in a new
	 * playlist. */
	if (!value &&
	    !(OP_ISSET & expr->kv.op) &&
	    (METADATA_IN_URL & (UINT64_C(1) << m)) &&
	    !ctx->pf.f->metadata[M_length])
		value = ctx->pf.f->a.url;
	else if (!value)
		return 0;

	if (OP_RE & expr->kv.op) {
		for (char const *s = value;;) {
			char *end = strchrnul(s, ';');

			int rc = pcre2_match(expr->kv.re,
					(uint8_t const *)s,
					end - s,
					0, 0, ctx->match_data, NULL);
			if (0 <= rc)
				return 1;
			assert(PCRE2_ERROR_NOMATCH == rc);

			if (!*end)
				return 0;
			s = end + 1;
		}
	} else {
		char const *s = value;
		for (uint8_t i = 0;;) {
			if (expr->kv.nnums <= i)
				return 1;

			uint64_t vn;
			if (!(s = expr_strtou64(s, &vn)))
				return 0;

			uint64_t n = expr->kv.nums[i++];
			enum KeyOp rel = OP_LT << ((vn > n) - (vn < n) + 1);
			if (rel & ~OP_EQ & expr->kv.op)
				return 1;
			if (rel & ((OP_LT | OP_EQ | OP_GT) ^ expr->kv.op))
				return 0;
		}
	}
}

static int
expr_eval(Expr const *expr, ExprEvalContext const *ctx)
{
	if (!expr)
		return 1;

	switch (expr->type) {
	case T_NEG:
		return !expr_eval(expr->un.expr, ctx);

	case T_AND:
		return expr_eval(expr->bi.lhs, ctx) && expr_eval(expr->bi.rhs, ctx);

	case T_OR:
		return expr_eval(expr->bi.lhs, ctx) || expr_eval(expr->bi.rhs, ctx);

	case T_KV:
		for (uint64_t keys = expr->kv.keys; keys;) {
			enum MetadataX m = __builtin_ctz(keys);
			keys ^= UINT64_C(1) << m;

			if (expr_eval_kv_key(expr, m, ctx))
				return 1;
		}
		return 0;

	default:
		abort();
	}
}

static void
expr_free(Expr *expr)
{
	if (!expr)
		return;

	switch (expr->type) {
	case T_NEG:
		expr_free(expr->un.expr);
		break;

	case T_AND:
	case T_OR:
		expr_free(expr->bi.lhs);
		expr_free(expr->bi.rhs);
		break;

	case T_KV:
		if (OP_RE & expr->kv.op)
			pcre2_code_free(expr->kv.re);
		break;

	default:
		abort();
	}

	free(expr);
}

static Expr *
expr_new(enum ExprType type)
{
#define EXPR_sizeof(u) (offsetof(Expr, u) + sizeof(((Expr *)0)->u))

	static size_t const EXPR_SZ[] = {
		[T_NEG] = EXPR_sizeof(un),
		[T_AND] = EXPR_sizeof(bi),
		[T_OR]  = EXPR_sizeof(bi),
		[T_KV]  = EXPR_sizeof(kv),
	};

#undef EXPR_sizeof

	Expr *expr = calloc(1, EXPR_SZ[type]);
	if (expr)
		expr->type = type;
	return expr;
}

static Expr *
expr_parse_kv(ExprParserContext *parser)
{
	Expr *expr = expr_new(T_KV);

	expr->kv.keys = 0;
	while (('a' <= *parser->ptr && *parser->ptr <= 'z') ||
	       ('A' <= *parser->ptr && *parser->ptr <= 'Z'))
	{
		char const *p;
		p = memchr(METADATA_LETTERS, *parser->ptr, sizeof METADATA_LETTERS);
		if (!p) {
			parser->error_msg = "Unknown key";
			goto fail;
		}
		++parser->ptr;

		enum MetadataX m = p - METADATA_LETTERS;
		expr->kv.keys |= UINT64_C(1) << m;
	}
	if (!expr->kv.keys)
		expr->kv.keys = METADATA_IN_URL;

	if ('?' == *parser->ptr) {
		++parser->ptr;
		expr->kv.op |= OP_ISSET;
	}

	switch (*parser->ptr) {
	case '~':
		++parser->ptr;
		/* FALLTHROUGH */
	default:
		expr->kv.op |= OP_RE;
		break;

	case '<':
		++parser->ptr;
		expr->kv.op |= OP_LT;
		goto may_eq;

	case '>':
		++parser->ptr;
		expr->kv.op |= OP_GT;
		goto may_eq;

	may_eq:
		if ('=' == *parser->ptr) {
	case '=':
			++parser->ptr;
			expr->kv.op |= OP_EQ;
		}
		break;
	}

	char const *p = parser->ptr;

	char buf[1 << 12];
	size_t buf_size = 0;
	char st = '"' == *p || '\'' == *p ? *p++ : '\0';

	for (; '\\' == *p ? *++p : *p && (st ? st != *p : ' ' != *p && '|' != *p && ')' != *p); ++p) {
		unsigned magic_sp = 0;
		if (' ' == *p) {
			unsigned escaped = 0;
			for (size_t i = buf_size; 0 < i && '\\' == buf[--i];)
				escaped ^= 1;
			magic_sp = !escaped;
		}

		if (magic_sp) {
			if (sizeof buf - 1 /* NUL */ - 6 < buf_size)
				goto fail_too_long;
			memcpy(buf + buf_size, "[._ -]+", 6);
			buf_size += 6;
		} else {
			if (sizeof buf - 1 /* NUL */ - 1 < buf_size)
				goto fail_too_long;
			buf[buf_size++] = *p;
		}
	}

	uint32_t re_flags = PCRE2_UTF | PCRE2_MATCH_INVALID_UTF;
	if (!buf_size) {
		re_flags |= PCRE2_LITERAL;

		PlaylistFile cur = parser->cur;
		if (!cur.f) {
			parser->error_msg = "No file is playing";
			goto fail;
		}

		for (uint64_t mxs = expr->kv.keys; mxs;) {
			enum MetadataX m = __builtin_ctz(mxs);
			mxs ^= UINT64_C(1) << m;

			char mbuf[FILE_METADATA_BUFSZ];
			char const *value = get_metadata(cur.p, cur.f, m, mbuf);
			if (!value)
				continue;

			while (*value && ';' != *value) {
				if (sizeof buf - 1 /* NUL */ - 1 < buf_size)
					goto fail_too_long;
				buf[buf_size++] = *value++;
			}
		}
	} else {
		re_flags |= PCRE2_DOTALL;
	}

	buf[buf_size] = '\0';


	if (OP_RE & expr->kv.op) {
		int rc = pcre2_match(re_ucase,
				(uint8_t const *)buf, buf_size, 0,
				0, parser->match_data, NULL);
		if (rc < 0) {
			assert(PCRE2_ERROR_NOMATCH == rc);
			re_flags |= PCRE2_CASELESS;
		}

		size_t error_offset;
		int error_code;
		expr->kv.re = pcre2_compile(
				(uint8_t const *)buf, buf_size, re_flags,
				&error_code, &error_offset, NULL);
		if (!expr->kv.re) {
			pcre2_get_error_message(error_code,
					(uint8_t *)parser->error_buf,
					sizeof parser->error_buf);
			parser->error_msg = parser->error_buf;
			goto fail;
		}

		(void)pcre2_jit_compile(expr->kv.re, PCRE2_JIT_COMPLETE);
	} else {
		char const *s = buf;
		expr->kv.nnums = 0;
		for (;;) {
			if (ARRAY_SIZE(expr->kv.nums) <= expr->kv.nnums) {
				parser->error_msg = "Too much numbers";
				goto fail;
			}

			if (!(s = expr_strtou64(s, &expr->kv.nums[expr->kv.nnums])))
				break;
			++expr->kv.nnums;
		}
	}

	if (*p && st)
		++p;

	parser->ptr = p;
	return expr;

fail_too_long:
	parser->error_msg = "Too long";
fail:
	assert(parser->error_msg);
	expr_free(expr);
	return NULL;
}

static int
expr_cost(Expr *expr)
{
	if (!expr)
		return 0;

	switch (expr->type) {
	case T_NEG:
		return 1 + expr_cost(expr->un.expr);

	case T_AND:
	case T_OR:
		return 2 + expr_cost(expr->bi.lhs) + expr_cost(expr->bi.rhs);

	case T_KV:
		if (OP_RE & expr->kv.op)
			return 1000 * __builtin_popcount(expr->kv.keys);
		else
			return 100;
		break;

	default:
		abort();
	}
}

static int
expr_depends_key(Expr const *expr, enum MetadataX m)
{
	if (!expr)
		return 0;

	switch (expr->type) {
	case T_NEG:
		return expr_depends_key(expr->un.expr, m);

	case T_AND:
	case T_OR:
		return expr_depends_key(expr->bi.lhs, m) || expr_depends_key(expr->bi.rhs, m);

	case T_KV:
		return !!(expr->kv.keys & (UINT64_C(1) << m));

	default:
		abort();
	}
}

static void
expr_optimize(Expr **pexpr)
{
	Expr *expr = *pexpr;
	if (!expr)
		return;

	switch (expr->type) {
	case T_NEG:
		expr_optimize(&expr->un.expr);

		/* Eliminate double negation. */
		if (T_NEG == expr->un.expr->type) {
			Expr **expr2 = &expr->un.expr->un.expr;
			*pexpr = *expr2;
			*expr2 = NULL;
			expr_free(expr);
		}

		return;

	case T_AND:
	case T_OR:
		expr_optimize(&expr->bi.lhs);
		expr_optimize(&expr->bi.rhs);

		/* X AND ZARY, ZARY AND X => X */
		if (T_AND == expr->type) {
			if (!expr->bi.lhs) {
				*pexpr = expr->bi.rhs;
				expr->bi.rhs = NULL;
				expr_free(expr);
				return;
			} else if (!expr->bi.rhs) {
				*pexpr = expr->bi.lhs;
				expr->bi.lhs = NULL;
				expr_free(expr);
				return;
			}
		}
		/* X OR ZARY, ZARY OR X => 1 */
		else if (!expr->bi.lhs || !expr->bi.rhs) {
			*pexpr = NULL;
			expr_free(expr);
			return;
		}

		/* Commutative => evaluate cheaper->expensive. */
		if (expr->type == expr->bi.rhs->type) {
			Expr **rlhs = &expr->bi.rhs->bi.lhs;
			if (expr_cost(expr->bi.lhs) > expr_cost(*rlhs)) {
				Expr *t = expr->bi.lhs;
				expr->bi.lhs = *rlhs;
				*rlhs = t;

				/* Re-optimize after change. */
				expr_optimize(&expr->bi.rhs);
			}
		} else if (expr_cost(expr->bi.lhs) > expr_cost(expr->bi.rhs)) {
			Expr *t = expr->bi.lhs;
			expr->bi.lhs = expr->bi.rhs;
			expr->bi.rhs = t;
		}

		return;

	case T_KV:
		return;

	default:
		abort();
	}
}

static Expr *
expr_parse(ExprParserContext *parser)
{
	Expr *lhs = NULL, *rhs;

	for (;;) {
		rhs = NULL;
		switch (*parser->ptr) {
		case '\0':
			return lhs;

		case ' ':
		case '\t':
		case '\r':
		case '\n':
			++parser->ptr;
			break;

		case '!':
		{
			++parser->ptr;
			rhs = expr_new(T_NEG);
			if (!rhs)
				goto fail_errno;
			if (!(rhs->un.expr = expr_parse(parser)))
				goto fail;
		}
			break;

		case '&':
		case '|':
		{
			if (!lhs) {
				parser->error_msg = "Missing left-hand side expression";
				goto fail;
			}

			rhs = expr_new('&' == *parser->ptr ? T_AND : T_OR);
			if (!rhs)
				goto fail_errno;
			++parser->ptr;
			if (!(rhs->bi.rhs = expr_parse(parser))) {
				if (!parser->error_msg)
					parser->error_msg = "Missing right-hand side expression";
				goto fail;
			}
			rhs->bi.lhs = lhs;
			lhs = NULL;
		}
			break;

		case '(':
			++parser->ptr;
			if (!(rhs = expr_parse(parser)))
				goto fail_unmatched;
			while (')' != *parser->ptr) {
				switch (*parser->ptr) {
				case ' ':
				case '\t':
					++parser->ptr;
					break;

				default:
				fail_unmatched:
					if (!parser->error_msg)
						parser->error_msg = "Unmatched (";
					goto fail;
				}
			}
			++parser->ptr;
			break;

		default:
			if (!(rhs = expr_parse_kv(parser)))
				goto fail;
		}

		if (!rhs) {
			/* Noop. */
		} else if (!lhs) {
			lhs = rhs;
			rhs = NULL;
		} else {
			/* Space operator: omitted &. */
			Expr *expr = expr_new(T_AND);
			if (!expr)
				goto fail_errno;
			expr->bi.lhs = lhs;
			expr->bi.rhs = rhs;
			lhs = expr;
		}
	}
	abort();

fail_errno:
	parser->error_msg = strerror(errno);
fail:
	assert(parser->error_msg);
	expr_free(lhs);
	expr_free(rhs);
	return NULL;
}

static void
match_file(PlaylistFile pf, MatchFileWorkerContext const *worker_ctx)
{
	assert(pf.f->a.type <= F_FILE);
	assert(worker_ctx->ctx.filter_index);

	uint32_t filter_mask = UINT32_C(1) << worker_ctx->ctx.filter_index;
	if (expr_eval(worker_ctx->ctx.query, &(ExprEvalContext const){
		.pf = pf,
		.match_data = worker_ctx->match_data,
	})) {
		pf.f->a.filter_mask |= filter_mask;
		atomic_fetch_add_lax(&pf.p->child_filter_count[worker_ctx->ctx.filter_index], 1);
	} else {
		pf.f->a.filter_mask &= ~filter_mask;
	}
}

static PlaylistFile
get_current_pf(void)
{
	PlaylistFile ret;
	ret.f = live ? in0.pf.f : sel;
	ret.p = ret.f ? get_parent(&master, &ret.f->a) : NULL;
	return ret;
}

static AnyFile *
get_playlist_start(Playlist const *playlist, int dir)
{
	return (void *)((char *)playlist->files + (0 <= dir
			? 0
			: playlist->files_size - get_file_size(playlist->last_child_type)
	));
}

static AnyFile *
get_playlist_end(Playlist const *playlist, int dir)
{
	return get_playlist_start(playlist, -dir);
}


static int64_t const POS_RND = INT64_MIN;

/* TODO: In playlists named ".queue", current file is always destroyed after
 * seeking. */
/* TODO: Append current entry to playlist named ".history". */
static PlaylistFile
seek_playlist_raw(Playlist const *root_playlist, uint8_t filter_index,
		PlaylistFile const *cur, int64_t pos, int whence)
{
	Playlist const *playlist = root_playlist;
	uint64_t max = playlist->child_filter_count[filter_index];
	if (!max)
		return (PlaylistFile){};

	if (SEEK_END == whence && POS_RND != pos) {
		pos += max - 1;
		whence = SEEK_SET;
	}

	int dir = 1;
	if (POS_RND == pos) {
		assert(cur);
		/* Tweak randomness a bit to make sure we do not play twice the
		 * same file one after another. */
		if (max <= 1)
			pos = 0;
		else
			pos = rndn(&rnd, max - 1) + 1;
		whence = SEEK_CUR;
	} else if (0 <= pos) {
		pos %= max;
	} else {
		pos = -pos % max;
		dir = -1;
	}

	AnyFile const *a;
	if (SEEK_CUR == whence && cur->f) {
		playlist = cur->p;
		a = &cur->f->a;
	} else {
		a = &playlist->a;
		playlist = playlist->parent;
	}

	for (;;) {
	check:
		if (F_FILE < a->type) {
			Playlist const *p = (void *)a;
			uint64_t n;

			n = p->child_filter_count[filter_index];
			if (n < (uint64_t)pos || !p->files_size) {
				/* Step over. */
				pos -= n;
			} else {
				/* Step in. */
				playlist = (void *)a;
				a = get_playlist_start(p, dir);
				continue;
			}
		}

		if (a->type <= F_FILE &&
		    ((UINT32_C(1) << filter_index) & a->filter_mask))
		{
			if (!pos)
				break;
			--pos;
		}

		while (playlist && get_playlist_end(playlist, dir) == a) {
			/* Wrap around. */
			if (root_playlist == playlist) {
				a = get_playlist_start(playlist, dir);
				goto check;
			}

			a = &playlist->a;
			playlist = ((Playlist *)a)->parent;
		}

		/* Step over. */
		if (0 <= dir)
			PTR_INC(a, get_file_size(a->type));
		else
			PTR_INC(a, -get_file_size(a->prev_type));
	}

	assert(a->type <= F_FILE);
	assert(F_FILE < playlist->a.type);
	return (PlaylistFile){ (Playlist *)playlist, (File *)a, };
}

static PlaylistFile
seek_playlist(Playlist const *playlist, PlaylistFile const *cur, int64_t pos, int whence)
{
	return seek_playlist_raw(playlist, cur_filter[live], cur, pos, whence);
}

static void *
task_worker(void *arg)
{
	FileTaskWorker *worker = arg;

#if HAVE_PTHREAD_SETNAME_NP
	char name[16];
	snprintf(name, sizeof name, "muck/worker%zu",
			(size_t)(worker - worker->task->workers));
	pthread_setname_np(pthread_self(), name);
#endif

	return (void *)(intptr_t)worker->task->routine(worker, worker->arg);
}

static int
for_each_file_par(int (*routine)(FileTaskWorker *, void const *), void const *arg)
{
	static int64_t const BATCH_SIZE_MIN = 16;
	static int64_t const BATCH_SIZE_MAX = 256;

	static long ncpus;
	if (!ncpus) {
		ncpus = sysconf(_SC_NPROCESSORS_ONLN);
		ncpus = FFMINMAX(1, ncpus, ARRAY_SIZE(((FileTask *)0)->workers));
	}

	FileTask task;

	xassert(0 <= pthread_mutex_init(&task.mutex, NULL));

	task.remaining = master.child_filter_count[0];
	if (1 < ncpus)
		task.batch_size = FFMINMAX(
				BATCH_SIZE_MIN,
				task.remaining / ncpus,
				BATCH_SIZE_MAX);
	else
		task.batch_size = task.remaining;
	task.cur = seek_playlist_raw(&master, 0, NULL, 0, SEEK_SET);

	task.nworkers = (task.remaining + task.batch_size - 1) / task.batch_size;
	task.nworkers = FFMIN(task.nworkers, ncpus);

	int rc;

	task.routine = routine;
	FileTaskWorker *worker = task.workers;
	for (;;) {
		*worker = (FileTaskWorker){
			.task = &task,
			.arg = arg,
		};

		if (worker < &task.workers[task.nworkers - 1] &&
		    0 <= pthread_create(&worker->thread, NULL, task_worker, worker))
		{
			++worker;
		} else {
			rc = task.routine(worker, arg);
			break;
		}
	}

	while (task.workers <= --worker)
		pthread_join(worker->thread, NULL);

	xassert(0 <= pthread_mutex_destroy(&task.mutex));

	return !task.remaining ? 0 : (assert(rc < 0), rc);
}

static int
worker_get(FileTaskWorker *worker, PlaylistFile *cur)
{
	if (!worker->count) {
		FileTask *task = worker->task;
		xassert(0 <= pthread_mutex_lock(&task->mutex));

		int64_t n = FFMIN(task->batch_size, task->remaining);
		worker->cur = task->cur;
		worker->count = n;
		task->remaining -= n;
		task->cur = seek_playlist_raw(&master, 0, &task->cur, n, SEEK_CUR);

		xassert(0 <= pthread_mutex_unlock(&task->mutex));

		if (!worker->count)
			return 0;
	}

	*cur = worker->cur;
	--worker->count;
	worker->cur = seek_playlist_raw(&master, 0, &worker->cur, 1, SEEK_CUR);

	return 1;
}

static int
spawn(void)
{
	fputs(STOP_FOCUS_EVENTS, tty);
	endwin();

	pid_t pid;
	if (!(pid = fork())) {
		xassert(!dup2(fileno(tty), STDIN_FILENO));

		struct sigaction sa;
		sigemptyset(&sa.sa_mask);

		sa.sa_handler = SIG_DFL;

		xassert(!sigaction(SIGCONT, &sa, NULL));
		xassert(!sigaction(SIGWINCH, &sa, NULL));
		xassert(!sigaction(SIGINT, &sa, NULL));
		xassert(!sigaction(SIGHUP, &sa, NULL));
		xassert(!sigaction(SIGTERM, &sa, NULL));
		xassert(!sigaction(SIGQUIT, &sa, NULL));
		xassert(!sigaction(SIGPIPE, &sa, NULL));
		xassert(!sigaction(SIGRTMIN, &sa, NULL));

		xassert(!pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL));
		return 0;
	}

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

	refresh();
	fputs(SEND_FOCUS_EVENTS, tty);

	return rc;
}

static void
show_messages(void)
{
	fflush(fmsg);
	if (!spawn()) {
		char const *pager = getenv("PAGER");
		if (!pager)
			pager = "less";
		execlp(pager, pager, "-rf", "-+ceEFX", "--", msg_path, NULL);
		_exit(EXIT_FAILURE);
	}
}

/* Reset match counts. */
static void
match_file_pre(Playlist *playlist, uint8_t filter_index)
{
	playlist->child_filter_count[filter_index] = 0;
	for_each_playlist(child, playlist)
		match_file_pre(child, filter_index);
}

/* Propagate match counts upwards. */
static void
match_file_post(Playlist *playlist, uint8_t filter_index)
{
	for_each_playlist(child, playlist) {
		match_file_post(child, filter_index);
		playlist->child_filter_count[filter_index] +=
				child->child_filter_count[filter_index];
	}
}

static int
match_file_worker(FileTaskWorker *worker, void const *arg)
{
	pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
	if (!match_data)
		return -ENOMEM;

	MatchFileWorkerContext worker_ctx = {
		.ctx = *(MatchFileContext *)arg,
		.match_data = match_data,
	};

	for (PlaylistFile pf; worker_get(worker, &pf);)
		match_file(pf, &worker_ctx);

	pcre2_match_data_free(match_data);
	return 0;
}

static void
search_file(char const *s)
{
	ExprParserContext parser = {};
	Expr *query = NULL;

	int old_live = live;
	live = 1;
	parser.cur = get_current_pf(),
	live = old_live;

	parser.match_data = pcre2_match_data_create(0, NULL);
	if (!parser.match_data) {
		parser.error_msg = "Out of memory";
		goto out;
	}

	parser.ptr = s;

	query = expr_parse(&parser);
	if (parser.error_msg) {
		endwin();
		/* TODO: Reopen visual search. */
		fprintf(tty, "<string>:%zu: error: %s\n",
				(size_t)(parser.ptr - s),
				parser.error_msg);
		fprintf(tty, "...%s\n", parser.ptr);
		getchar();
		refresh();
		goto out;
	}

	if (!expr_depends_key(query, MX_playlist)) {
		parser.ptr = "p~^[^-]";

		Expr *expr = expr_new(T_AND);
		if (!expr)
			goto out;
		if (!(expr->bi.rhs = expr_parse(&parser))) {
			expr_free(expr);
			goto out;
		}
		expr->bi.lhs = query;
		query = expr;
	}

	expr_optimize(&query);

	/* TODO: Cache filters. */
	cur_filter[live] = 1 + live;

	uint32_t filter_index = cur_filter[live];

	match_file_pre(&master, filter_index);
	(void)for_each_file_par(match_file_worker, &(MatchFileContext const){
		.query = query,
		.filter_index = filter_index,
	});
	match_file_post(&master, filter_index);

out:
	pcre2_match_data_free(parser.match_data);

	expr_free(query);
}

static void
notify_progress(void)
{
	if (!atomic_load_lax(&focused))
		return;

	int64_t pts = atomic_load_lax(&cur_pts);
	int64_t duration = atomic_load_lax(&cur_duration);

	if (pts == notify_pts && duration == notify_duration)
		return;

	notify_pts = pts;
	notify_duration = duration;

	notify_event(EVENT_STATE_CHANGED);
}

static void
do_wakeup(int *which0, int *which1)
{
	xassert(!pthread_mutex_lock(&buffer_lock));
	*which0 = 1;
	if (which1)
		*which1 = 1;
	xassert(!pthread_cond_broadcast(&buffer_wakeup));
	xassert(!pthread_mutex_unlock(&buffer_lock));
}

static void
wait_wakeup(int *which)
{
	xassert(!pthread_mutex_lock(&buffer_lock));
	while (!*which)
		xassert(!pthread_cond_wait(&buffer_wakeup, &buffer_lock));
	*which = 0;
	xassert(!pthread_mutex_unlock(&buffer_lock));
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

	int64_t duration = atomic_load_lax(&cur_duration);
	if (ts < 0)
		ts = 0;
	else if (duration < ts)
		ts = duration;

	atomic_store_lax(&seek_pts, ts);
	do_wakeup(&wakeup_source, NULL);
}

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

static void do_key(int c);

static void *
source_worker(void *arg)
{
	(void)arg;

	pthread_setname_np(pthread_self(), "muck/source");

	AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		print_error("Could not allocate memory");
		goto terminate;
	}

	int flush_output = 0;
	enum {
		S_RUNNING,
		S_STOPPED,
		S_STALLED,
	} state = S_STALLED;
	int64_t buffer_full_bytes = buffer_bytes_max;

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
				close_input(&in0);

				atomic_store_lax(&in0.pf.f, seek_file0);
				seek_file0 = NULL;
				in0.pf.p = get_parent(&master, &in0.pf.f->a);

				open_input(&in0);
				update_cover(&in0);
				update_input_info();
				if (atomic_load_lax(&focused))
					notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);

				/* Otherwise would be noise. */
				if (in0.s.codec_ctx) {
					state = S_RUNNING;
				} else {
					xassert(!pthread_mutex_unlock(&file_lock));
					/* Do not flush buffer yet. */
					goto seek;
				}

				seek_buffer(INT64_MIN);
				atomic_store_lax(&seek_pts, seek_file_pts);

				flush_output = 0; /* TODO: Eh... seek by user =>flush or automatic =>no flush? */
			}
			xassert(!pthread_mutex_unlock(&file_lock));
		}

		if (unlikely(atomic_load_lax(&dump_in0))) {
			int old_level = av_log_get_level();
			av_log_set_level(AV_LOG_DEBUG); /* <-- Not atomic. */
			if (in0.s.format_ctx)
				av_dump_format(in0.s.format_ctx, 0,
						in0.pf.f ? in0.pf.f->a.url : "(none)", 0);
			av_log_set_level(old_level);
			/* It is not an exchange. */
			atomic_store_lax(&dump_in0, 0);
		}

		int64_t target_pts = atomic_exchange_lax(&seek_pts, AV_NOPTS_VALUE);
		if (unlikely(AV_NOPTS_VALUE != target_pts && in0.s.codec_ctx)) {
			/* A cheap way to save decoding a frame immediately but
			 * still showing something. */
			atomic_store_lax(&cur_pts, target_pts);

			state = S_RUNNING;

			target_pts = av_rescale(target_pts,
					in0.s.audio->time_base.den,
					in0.s.audio->time_base.num);

			if (seek_buffer(target_pts))
				goto wakeup_sink;

			flush_output = 1;

			/* Maybe interesting: out.codec_ctx->delay. */

			avcodec_flush_buffers(in0.s.codec_ctx);
			rc = avformat_seek_file(in0.s.format_ctx, in0.s.audio->index,
					0, target_pts, target_pts, 0);
			if (rc < 0)
				print_averror("Could not seek", rc);
		}

		if (unlikely(S_STALLED <= state) ||
		    unlikely(atomic_load_lax(&paused)) ||
		    (0 < buffer_low ? buffer_low : buffer_bytes_max) <=
			atomic_load_explicit(&buffer_bytes, memory_order_acquire) ||
		    (unlikely(buffer_tail + 1 == atomic_load_lax(&buffer_head)) &&
		     (buffer_full_bytes = atomic_load_lax(&buffer_bytes), 1)))
		{
		wait:;
			if (S_STOPPED == state &&
			    atomic_load_lax(&buffer_head) == atomic_load_lax(&buffer_tail)) {
			seek:;
				state = S_STALLED;
				/* TODO: Seek commands should fill in1 first. */
				notify_event(EVENT_EOF_REACHED);
			}

			atomic_store_lax(&buffer_low, S_RUNNING == state
					? buffer_full_bytes / 2
					: 0);
			wait_wakeup(&wakeup_source);
			continue;
		}

		AVFrame *frame = buffer[buffer_tail];

		if (!frame) {
			for (uint16_t to = atomic_load_lax(&buffer_head);
			     buffer_reap < to;
			     ++buffer_reap)
				if ((frame = buffer[buffer_reap])) {
					buffer[buffer_reap++] = NULL;
					break;
				}

			if (unlikely(!frame) &&
			    unlikely(!(frame = av_frame_alloc())))
			{
				print_error("Could not allocate memory");
				state = S_STOPPED;
				goto wait;
			}
			buffer[buffer_tail] = frame;
		}

		Input *in = &in0;

		rc = av_read_frame(in->s.format_ctx, pkt);
		if (unlikely(state = rc < 0 ? S_STOPPED : S_RUNNING)) {
			if (AVERROR_EOF != rc)
				print_averror("Could not read frame", rc);
			goto wait;
		}

		/* Packet from an uninteresting stream. */
		if (unlikely(in->s.audio->index != pkt->stream_index)) {
			av_packet_unref(pkt);
			continue;
		}

		if (unlikely((AVSTREAM_EVENT_FLAG_METADATA_UPDATED & in->s.format_ctx->event_flags))) {
			in->s.format_ctx->event_flags &= ~AVSTREAM_EVENT_FLAG_METADATA_UPDATED;

			AVDictionaryEntry const *t;
			t = av_dict_get(in->s.format_ctx->metadata,
					"StreamTitle", NULL, 0);
			if (t) {
				char buf[20];
				time_t now = time(NULL);
				struct tm *tm = localtime(&now);
				strftime(buf, sizeof buf, "%a %d %R", tm);
				fprintf(fmsg, "%s ICY: %s\n", buf, t->value);
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
			frame->opaque = (void *)(size_t)flush_output;
			flush_output = 0;

			atomic_store_lax(&cur_duration,
					AV_NOPTS_VALUE == in0.s.format_ctx->duration
						? frame->pts
						: av_rescale(in0.s.format_ctx->duration, 1, AV_TIME_BASE));

			int was_empty =
				atomic_load_lax(&buffer_head) ==
				atomic_fetch_add_explicit(&buffer_tail, 1, memory_order_release);
			if (unlikely(was_empty)) {
			wakeup_sink:
				do_wakeup(&wakeup_sink, NULL);
			}

			notify_progress();
		} else if (AVERROR(EAGAIN) != rc)
			print_averror("Could not decode frame", rc);
	}

terminate:
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

	pthread_setname_np(pthread_self(), "muck/sink");

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
			flush_output();
			goto wait;
		}

		uint16_t head = atomic_load_lax(&buffer_head);
		if (unlikely(head == atomic_load_explicit(&buffer_tail, memory_order_acquire)))
			goto wait;

		if (0) {
		wait:
			wait_wakeup(&wakeup_sink);
			continue;
		}

		frame = atomic_exchange_lax(&buffer[head], frame);
		/* If head stayed the same we can be sure that picked frame is valid. */
		if (unlikely(!atomic_compare_exchange_strong_explicit(
				&buffer_head, &head, head + 1,
				memory_order_relaxed, memory_order_relaxed)))
			continue;

		int rc;

		int64_t rem_bytes = atomic_fetch_sub_lax(&buffer_bytes, frame->pkt_size) - frame->pkt_size;
		assert(0 <= rem_bytes);
		if (rem_bytes <= atomic_load_lax(&buffer_low)) {
			atomic_store_lax(&buffer_low, INT64_MIN);
			do_wakeup(&wakeup_source, NULL);
		}

		int graph_changed = 0;
#define xmacro(x) (graph_changed |= pars->x != frame->x, pars->x = frame->x)
		xmacro(format);
		xmacro(sample_rate);
		xmacro(channel_layout);
#undef xmacro

		rc = configure_output(frame);
		if ((!rc && unlikely(graph_changed)) ||
		    unlikely(0 < rc))
			rc = configure_graph(pars);
		if (unlikely(rc < 0)) {
			atomic_store_lax(&paused, 1);
			notify_event(EVENT_STATE_CHANGED);
			continue;
		}

		int desired_volume = atomic_load_lax(&volume);
		if (desired_volume < 0)
			desired_volume = 0;
		if (unlikely(graph_volume_volume != desired_volume)) {
			graph_volume_volume = desired_volume;

			double farg = pow(desired_volume / 100., M_E);
			char arg[50];
			snprintf(arg, sizeof arg, "%f", farg);

			rc = avfilter_graph_send_command(graph,
					"volume", "volume",
					arg, NULL, 0, 0);
			if (rc < 0) {
				if (!avfilter_graph_get_filter(graph, "volume"))
					print_error("Cannot find 'volume' filter");
				print_error("Could not set volume");
			}
		}

		if (unlikely(frame->opaque))
			flush_output();

		atomic_store_lax(&cur_pts, frame->pts);

		notify_progress();

		frame->pts = out_dts;
		frame->pkt_dts = out_dts;
		frame->pkt_duration =
			frame->nb_samples
			* out.audio->time_base.den
			/ frame->sample_rate
			/ out.audio->time_base.num;

		rc = av_buffersrc_add_frame_flags(buffer_ctx, frame,
				AV_BUFFERSRC_FLAG_NO_CHECK_FORMAT);
		if (unlikely(rc < 0))
			print_averror("Could not push frame into filtergraph", rc);

		rc = av_buffersink_get_frame_flags(buffersink_ctx, frame, 0);
		if (unlikely(rc < 0))
			print_averror("Could not pull frame from filtergraph", rc);

		/* Send a frame to encode. */
		rc = avcodec_send_frame(out.codec_ctx, frame);
		if (unlikely(rc < 0))
			print_averror("Could not encode frame", rc);

		av_frame_unref(frame);

		/* Receive an encoded packet. */
		while (0 <= (rc = avcodec_receive_packet(out.codec_ctx, pkt))) {
			out_dts += pkt->duration;

			rc = av_write_frame(out.format_ctx, pkt);
			if (unlikely(rc < 0))
				print_averror("Could not write encoded frame", rc);
			av_packet_unref(pkt);
		}
		if (unlikely(AVERROR(EAGAIN) != rc))
			print_averror("Could not receive encoded frame", rc);
	}

terminate:
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
bye(void)
{
	fputs(STOP_FOCUS_EVENTS, tty);
	endwin();

	xassert(!pthread_mutex_lock(&file_lock));
	save_master();
	xassert(!pthread_mutex_unlock(&file_lock));

#if CONFIG_VALGRIND
	if (threads_inited) {
		atomic_store_lax(&terminate, 1);
		do_wakeup(&wakeup_source, &wakeup_sink);

		xassert(!pthread_join(source_thread, NULL));

		xassert(!pthread_join(sink_thread, NULL));
	}

	xassert(!pthread_mutex_destroy(&buffer_lock));
	xassert(!pthread_mutex_destroy(&file_lock));
	xassert(!pthread_cond_destroy(&buffer_wakeup));

	cleanup_file(&master.a);

	close_input(&in0);
	close_output();
	close_graph();

	pcre2_code_free(re_ucase);

	uint16_t i = 0;
	do
		av_frame_free(&buffer[i]);
	while ((uint16_t)++i);

	for (size_t i = 0; i < ARRAY_SIZE(search_history); ++i)
		free(search_history[i]);
#endif
}

static void
play_file(File *f, int64_t pts)
{
	/* Mutex will acquire. */
	atomic_store_lax(&seek_file_pts, pts);
	atomic_store_lax(&seek_file0, f);
	do_wakeup(&wakeup_source, NULL);
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
		print_strerror("Failed to create temporary file");
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
	for (size_t i = 0; i < ARRAY_SIZE(search_history) && search_history[i]; ++i)
	{
		fprintf(stream, "%s\n", search_history[i]);
		any = 1;
	}
	if (!any)
		fputc('\n', stream);
	fputc('\n', stream);

	PlaylistFile cur = get_current_pf();
	if (cur.f) {
		for (enum MetadataX i = 0; i < MX_NB; ++i) {
			char mbuf[FILE_METADATA_BUFSZ];
			char const *value = get_metadata(cur.p, cur.f, i, mbuf);
			if (!value || !*value)
				continue;

			fputc(METADATA_LETTERS[i], stream);
			fputc('~', stream);
			fputc('\'', stream);
			fputs(value, stream);
			fputc('\'', stream);
			fputc('\n', stream);
		}
		fputc('\n', stream);
	}

	char history_path[PATH_MAX];
	snprintf(history_path, sizeof history_path,
			"%s/%s", config_home, "search-history");
	FILE *history = fopen(history_path, "re");
	char const *home = getenv("HOME");
	size_t home_size = strlen(home);
	int tilde = !strncmp(history_path, home, home_size);
	fprintf(stream, "# %s%s:\n",
			tilde ? "~" : "",
			history_path + (tilde ? home_size : 0));
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
"# FIRST-LINE := EXPR\n"
"# EXPR := [KEY]... [ \"?\" ] [ { \"<\" | \">\" }[ \"=\" ] | \"~\" ] [VALUE]\n"
"# EXPR := EXPR \"&\" EXPR | EXPR EXPR\n"
"# EXPR := EXPR \"|\" EXPR\n"
"# EXPR := \"!\" EXPR\n"
"# VALUE := QUOTED | WORD\n"
"# QUOTED := \"'\" [ all characters - \"'\" ]... \"'\"\n"
"# QUOTED := '\"' [ all characters - '\"' ]... '\"'\n"
"# WORD := { all characters - \"'\", '\"', \" \", \"|\", \")\" } [ all characters - \" \", \"|\", \")\" ]...\n"
"# KEY := {\n"
			);
	for (enum MetadataX i = 0; i < MX_NB; ++i) {
		char mbuf[FILE_METADATA_BUFSZ];
		char const *value = cur.f ? get_metadata(cur.p, cur.f, i, mbuf) : NULL;
		fprintf(stream, "#  %c%c=%-*s%s\n",
				METADATA_IN_URL & (UINT64_C(1) << i) ? '+' : ' ',
				METADATA_LETTERS[i],
				value && *value ? (int)sizeof METADATA_NAMES[i] : 0,
				METADATA_NAMES[i],
				value ? value : "");
	}
	fprintf(stream,
"# }\n"
"#\n"
"# If KEY is omitted it defaults to keys marked with \"+\".\n"
"#   Example:\n"
"#     ~love.*bugs\n"
"#     'all star'\n"
"#   Searches artist, title, url, codec, comment...\n"
"#\n"
"# When multiple KEYs are specified it matches when any of them is\n"
"# matching.\n"
"#   Example:\n"
"#     ax^Don & tT~peace\n"
"#   artist (a) or remixer (x) field starts with Don (case-sensitive) and\n"
"#   title (t) album (T) contains \"peace\".\n"
"#\n"
"# \"~\" tests whether given PCRE (VALUE) matches metadata.\n"
"# May be omitted since it is the default.\n"
"#\n"
"# \"<\", \">\" compares pairs of integers. All non-digits are ignored.\n"
"#   Example:\n"
"#     y<2001.02.03.\n"
"#   Matches songs with y~'2000', y~'2000-04.10', y~'2001X02',\n"
"#   y~'xyz 2001 abc 2/1'.\n"
"#     y<=2001.02.03\n"
"#   Also matches y='2001-02-03'\n"
"#     o~flac o>44 \n"
"#   High-resolution FLAC files.\n"
"#\n"
"# If VALUE is omitted it is taken from the currently playing file.\n"
"# For KEYs with multiple occurences only the first one is considered.\n"
"#   Example:\n"
"#     T\n"
"#     y A T\n"
"#   Match tracks from the same album.\n"
"#     A (same as: A~'Good')\n"
"#   With currently playing having A='Good;Bad;Ugly'.\n"
"#\n"
"# VALUE is matched caseless unless it contains uppercase letter.\n"
"#   Example:\n"
"#     t~ear (case-insensitive)\n"
"#     t~Ear (case-sensitive)\n"
"#   Both match songs named 'Ear' but only the first one matches 'Heart'.\n"
"#\n"
"# If file has no tags, KEYs marked with \"+\" match VALUE against URL.\n"
"# This behavior can be avoided by \"?\".\n"
"#   Example:\n"
"#     a~jimmy t~sunshine\n"
"#   For unscanned files both 'jimmy' and 'sunshine' are searched in URL,\n"
"#   thus it will match appropriately named files, e.g. 'Jimmy - Sunshine.mp3'.\n"
"#     a?jimmy\n"
"#   May return nothing.\n"
"#     n?.\n"
"#   Use \".\" (match any) after \"?\" to test whether key is set.\n"
"#\n"
"# Between expressions \"!\", \"&\", \"|\" can be used to express\n"
"# negation, and and or operations, respectively. \"&\" is the default so it\n"
"# can be omitted. \"(\", \")\" can be used for grouping.\n"
"#   Example:\n"
"#     !(g~rock y<2000)\n"
"#   All but rock before 2000.\n"
"#\n"
			);

	fclose(stream);

	int rc = spawn();
	if (!rc) {
		char const *editor = getenv("EDITOR");
		execlp(editor, editor, "--", tmpname, NULL);
		_exit(EXIT_FAILURE);
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
			notify_event(EVENT_FILE_CHANGED);
		}
	}

	unlink(tmpname);
}

static void
pause_player(int pause)
{
	atomic_store_lax(&paused, pause);
	if (!pause)
		do_wakeup(&wakeup_source, &wakeup_sink);
	notify_event(EVENT_STATE_CHANGED);
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
play_or_select_file(File *f)
{
	if (live) {
		play_file(f, AV_NOPTS_VALUE);
	} else {
		sel = f;
		notify_event(EVENT_FILE_CHANGED);
	}
}

static void
use_number(char c, int64_t def)
{
	if ('0' == number_cmd[live])
		number_cmd[live] = c;
	else if (c != number_cmd[live])
		cur_number[live] = def;
}

static int64_t
get_number(int64_t def)
{
	if ('0' == number_cmd[live])
		return cur_number[live];
	else
		return def;
}

static void
spawn_script(int c)
{
	PlaylistFile pf = get_current_pf();
	struct timespec mtim_before = get_file_mtim(pf);

	if (!spawn()) {
		if (pf.p &&
		    AT_FDCWD != pf.p->dirfd &&
		    fchdir(pf.p->dirfd) < 0)
		{
			print_error("Could not change working directory");
			_exit(EXIT_FAILURE);
		}

		if (pf.f) {
			if (F_FILE == pf.f->a.type)
				setenv("MUCK_PATH", pf.f->a.url, 0);

			char name[5 + sizeof *METADATA_NAMES] = "MUCK_";

			for (enum MetadataX m = 0; m < MX_NB; ++m) {
				memcpy(name + 5, METADATA_NAMES[m], sizeof *METADATA_NAMES);
				char mbuf[FILE_METADATA_BUFSZ];
				char const *value = get_metadata(pf.p, pf.f, m, mbuf);
				if (value)
					setenv(name, value, 0);
			}
		}

		char exe[PATH_MAX];
		snprintf(exe, sizeof exe, "%s/%c", config_home, c);
		execl(exe, exe, pf.f->a.url, NULL);
		print_error("No binding for '%c'", c);

		_exit(EXIT_FAILURE);
	}

	struct timespec mtim_after = get_file_mtim(pf);

	if (memcmp(&mtim_before, &mtim_after, sizeof mtim_before))
		play_file(pf.f, atomic_load_lax(&cur_pts));
}

static void
do_key(int c)
{
	if ('0' <= c && c <= '9') {
		cur_number[live] = 10 * get_number(0) + (c - '0');
		number_cmd[live] = '0';
		notify_event(EVENT_STATE_CHANGED);
		return;
	}

	switch (c) {
	case CONTROL('D'):
		number_cmd[live] = '0';
		cur_number[live] = (LINES - 2) / 2;
		c = 'n';
		break;

	case CONTROL('U'):
		number_cmd[live] = '0';
		cur_number[live] = (LINES - 2) / 2;
		c = 'p';
		break;

	case CONTROL('M'):
		if (live)
			c = seek_cmd;
		break;
	}

	switch (c) {
	case '*':
		atomic_store_lax(&volume, get_number(-volume));
		notify_event(EVENT_STATE_CHANGED);
		break;

	case '+':
		atomic_store_lax(&volume, FFMIN(abs(volume) + 1, 100));
		notify_event(EVENT_STATE_CHANGED);
		break;

	case '-':
		atomic_store_lax(&volume, FFMAX(0, abs(volume) - 2));
		notify_event(EVENT_STATE_CHANGED);
		break;

	case 'M': /* Metadata. */
		atomic_store_lax(&dump_in0, 1);
		do_wakeup(&wakeup_source, NULL);
		break;

	case 'm':
		show_messages();
		break;

	case CONTROL('I'):
		/* TODO: Switch show information / currently playing tabs. */
		break;

	case 'v':
		if (atomic_fetch_xor_explicit(&live, 1, memory_order_relaxed))
			atomic_store_lax(&sel, atomic_load_lax(&in0.pf.f));
		/* Keep values on entering visual mode. */
		cur_filter[0] = cur_filter[1];
		cur_number[0] = cur_number[1];
		number_cmd[0] = '\0';
		number_cmd[1] = '\0';
		notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);
		break;

	case 't': /* Tracks. */
	{
		unsigned n = atomic_load_lax(&in0.nb_audios);
		if (n) {
			atomic_store_lax(&cur_track, (cur_track + 1) % n);
			play_file(atomic_load_lax(&in0.pf.f), atomic_load_lax(&cur_pts));
		}
	}
		break;

	case '/': /* Search. */
		open_visual_search();
		if (live) {
			PlaylistFile cur = get_current_pf();
			PlaylistFile pf = seek_playlist(&master, &cur, 0, SEEK_CUR);
			if (pf.f != cur.f)
				play_file(pf.f, AV_NOPTS_VALUE);
		}
		break;

	case '|':
		/* TODO: Plumb master playlist. */
		plumb_file(&master.a, cur_filter[live], stdout);
		break;

	case 'e': /* Edit. */
	{
		if (live) {
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
		plumb_file(&master.a, cur_filter[live], stream);
		fclose(stream);

		if (!spawn()) {
			char const *editor = getenv("EDITOR");
			execlp(editor, editor, "--", tmpname, NULL);
			_exit(EXIT_FAILURE);
		}

		unlink(tmpname);
	}
		break;

	case 'r': /* Random. */
		if (live) {
			char old_seek_cmd = seek_cmd;
			seek_cmd = 'r';
			notify_event(EVENT_STATE_CHANGED);
			if ('g' == old_seek_cmd)
				break;
		}

		PlaylistFile cur = get_current_pf();
		PlaylistFile pf = seek_playlist(&master, &cur, POS_RND, SEEK_SET);
		play_or_select_file(pf.f);
		break;

	case 's': /* Set. */
	{
		int64_t n = get_number(0);

		if (live) {
			/* Stay close to file, even if it fails to play. */
			if ('p' != seek_cmd && 'n' != seek_cmd) {
				seek_cmd = 'n';
				number_cmd[live] = '\0';
				notify_event(EVENT_STATE_CHANGED);
			}
		}

		PlaylistFile pf = seek_playlist(&master, NULL, n, SEEK_SET);
		play_or_select_file(pf.f);
	}
		break;

	case 'n': /* Next. */
	case KEY_DOWN:
	case 'N':
	case 'p': /* Previous. */
	case KEY_UP:
	{
		char old_seek_cmd = seek_cmd;
		int dir = 'n' == c || KEY_DOWN == c ? 1 : -1;
		if (live)
			seek_cmd = 0 < dir ? 'n' : 'p';
		use_number('n', 1);
		notify_event(EVENT_STATE_CHANGED);

		if ('g' == old_seek_cmd)
			break;

		PlaylistFile cur = get_current_pf();
		PlaylistFile pf = seek_playlist(&master, &cur,
				cur_number[live] * dir, SEEK_CUR);
		play_or_select_file(pf.f);
	}
		break;

	case 'g': /* Go to. */
	case KEY_HOME:
	{
		if (live)
			seek_cmd = 'g';
		use_number('g', 0);
		notify_event(EVENT_STATE_CHANGED);

		if (live) {
			uint64_t ts =
				cur_number[live] / 100 * 60 /* min */ +
				cur_number[live] % 100 /* sec */;
			seek_player(ts, SEEK_SET);
		} else {
			sel = seek_playlist(&master, NULL, 0, SEEK_SET).f;
			notify_event(EVENT_FILE_CHANGED);
		}
	}
		break;

	case 'G': /* GO TO. */
	case KEY_END:
		if (live) {
			int64_t n = get_number(100 * 3 / 8);
			seek_player(atomic_load_lax(&cur_duration) * n / 100, SEEK_SET);
		} else {
			sel = seek_playlist(&master, NULL, 0, SEEK_END).f;
			notify_event(EVENT_FILE_CHANGED);
		}
		break;

	case 'H':
	case KEY_SLEFT:
	case 'L':
	case KEY_SRIGHT:
		scroll_x += 'H' == c || KEY_SLEFT == c ? -1 : 1;
		notify_event(EVENT_FILE_CHANGED);
		break;

	case 'h':
	case KEY_LEFT:
	case 'l':
	case KEY_RIGHT:
	{
		int dir = 'h' == c || KEY_LEFT == c ? -1 : 1;
		int64_t n = get_number(5);
		seek_player(n * dir, SEEK_CUR);
	}
		break;

	case 'j':
	case 'k':
	{
		int dir = 'j' == c ? -1 : 1;
		if (live) {
			int64_t n = get_number(FFMAX(atomic_load_lax(&cur_duration) / 16, +5));
			seek_player(n * dir, SEEK_CUR);
		} else {
			PlaylistFile cur = get_current_pf();
			int64_t n = get_number(1);
			sel = seek_playlist(&master, &cur, n * -dir, SEEK_CUR).f;
			notify_event(EVENT_FILE_CHANGED);
		}
	}
		break;

	case '.':
	case '>':
		pause_player('.' == c);
		break;

	case 'c': /* Continue. */
	case ' ':
		pause_player(!paused);
		break;

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

	case 'w':
		widen ^= 1;
		notify_event(EVENT_FILE_CHANGED);
		break;

	case '?':
	case KEY_F(1):
		if (!spawn()) {
			execlp("man", "man", "muck.1", NULL);
			print_strerror("Could not open manual page");
			_exit(EXIT_FAILURE);
		}
		break;

	case CONTROL('L'):
		clear();
		notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);
		break;

	case CONTROL('M'):
		play_file(get_current_pf().f, AV_NOPTS_VALUE);
		pause_player(0);
		break;

	case 'Z': /* Zzz. */
	case 'Q':
	case 'q':
	case KEY_F(10):
		exit(EXIT_SUCCESS);

	default:
		if (' ' <= c && c <= '~')
			spawn_script(c);
		break;

	case KEY_FOCUS_IN:
	case KEY_FOCUS_OUT:
		atomic_store_lax(&focused, KEY_FOCUS_IN == c);
		notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);
		break;
	}

	if ('0' == number_cmd[live]) {
		number_cmd[live] = '\0';
		cur_number[live] = 0;
		notify_event(EVENT_STATE_CHANGED);
	}
}

static void
do_keys(char const *s)
{
	while (*s)
		do_key(*s++);
}

static void
log_cb(void *ctx, int level, char const *format, va_list ap)
{
	(void)ctx;

	if (av_log_get_level() < level)
		return;

	flockfile(fmsg);
	if (level <= AV_LOG_ERROR)
		fputs("\033[1;31m", fmsg);
	vfprintf(fmsg, format, ap);
	if (level <= AV_LOG_ERROR)
		fputs("\033[m", fmsg);
	funlockfile(fmsg);
}

static void
draw_cursor(void)
{
	move(sel_y, sel_x);
}

static void
update_title(File const *f)
{
	fputs("\033]0;", tty);
	if (f && f->metadata[M_title]) {
		/* Note that metadata is free from control characters. */
		fputs(f->a.url + f->metadata[M_title], tty);
		if (f->metadata[M_version])
			fprintf(tty, " (%s)", f->a.url + f->metadata[M_version]);
	} else if (f) {
		fputs(f->a.url, tty);
	} else {
		fputs("muck", tty);
	}
	fputc('\a', tty);
}

static void
draw_files(void)
{
	enum { SHORT_WIDTH = 10, };

	typedef struct {
		char mod;
		int width;
		union {
			enum Metadata m;
			enum MetadataX mx;
		};
	} ColumnDef;

	ColumnDef defs[2 * MX_NB];

	/* Parse columns specification. */
	int stars = 0;
	int nc = 0;
	int totw = 0;

	if (scroll_x < 0)
		scroll_x = 0;

	ColumnDef *c = defs;
	for (char const *s = column_spec; *s;) {
		char mod = '\0';
		if ('*' <= *s && *s <= '/')
			mod = *s++;
		int iscol = !mod || '*' == mod;

		if (iscol && COLS < totw)
			break;

		char *end;
		int n = strtol(s, &end, 10);

		char const *p;
		if (!(p = memchr(METADATA_LETTERS, *end, sizeof METADATA_LETTERS)))
			break;
		enum MetadataX mx = p - METADATA_LETTERS;

		if (s == end) {
			if (MX_index == mx && master.child_filter_count[0])
				n = ceil(log(master.child_filter_count[0]) / log(10));
			else
				n = METADATA_COLUMN_WIDTHS[mx];
		}

		c->mod = mod;
		c->width = n;
		c->mx = mx;

		int w = widen && SHORT_WIDTH < c->width;
		for (ColumnDef const *t = defs; w && t < c; ++t)
			w &= t->width <= SHORT_WIDTH;
		if (w)
			c->width = 2 * c->width < COLS ? COLS / 2 + 1 : COLS;

		stars += '*' == c->mod;
		if (iscol)
			totw += c->width + 1 /* SP */;

		s = end + 1;

		if (iscol ? ++nc <= scroll_x : nc == scroll_x) {
			c = defs;
			totw = 0;
			stars = 0;
			continue;
		}

		if ((&defs)[1] <= ++c)
			break;
	}

	if (nc < scroll_x)
		scroll_x = nc;

	ColumnDef *endc = c;

	/* Expand flexible columns. */
	for (c = defs; c < endc && 0 < stars; ++c)
		if ('*' == c->mod) {
			c->mod = '\0';
			int n = (COLS - totw) / stars--;
			if (0 < n) {
				totw += n;
				c->width += n;
			}
		}

	/* Scroll to make current file visible. */
	PlaylistFile start = seek_playlist(&master, NULL, 0, SEEK_SET);
	PlaylistFile end = seek_playlist(&master, NULL, 0, SEEK_END);

	int win_lines = LINES - 2;

	File const *playing = atomic_load_lax(&in0.pf.f);
	PlaylistFile cur = get_current_pf();
	PlaylistFile pos = cur;
	int seen_top = 0;
	int dist = 0;
	int scrolloff = 5;
	for (;;) {
		if (pos.f == start.f)
			break;
		seen_top |= pos.f == top.f;
		if ((seen_top && scrolloff <= dist) || win_lines - scrolloff - 1 <= dist)
			break;
		pos = seek_playlist(&master, &pos, -1, SEEK_CUR);
		++dist;
	}
	if (top.f) {
		int dir = get_file_index(top) < get_file_index(pos) ? 1 : -1;
		int scroll = 0;
		while (top.f != pos.f && abs(scroll) <= LINES) {
			top = seek_playlist(&master, &top, dir, SEEK_CUR);
			scroll += dir;
		}

		if (scroll && abs(scroll) <= LINES) {
			scrollok(stdscr, TRUE);
			scrl(scroll);
			scrollok(stdscr, FALSE);
		}
	}
	top = pos;

	/* Draw header. */
	move(0, 0);
	attr_set(A_REVERSE, 0, NULL);
	for (c = defs; c < endc; ++c) {
		if (c->mod)
			continue;

		char const *name = METADATA_NAMES[c->m];
		int i = 0;

		for (; name[i] && i < c->width; ++i) {
			char t;
			switch (name[i]) {
			case '_':
				t = ' ';
				break;

			default:
				t = name[i] - 'a' + 'A';
				break;
			}
			addch(t);
		}

		for (; i <= c->width; ++i)
			addch(' ');
	}
	for (int curx = getcurx(stdscr); curx < COLS; ++curx)
		addch(' ');

	/* Draw lines. */
	sel_y = 0, sel_x = 0;

	int line = 1;
	for (;;) {
		if (win_lines < line)
			break;
		if (!pos.f)
			break;

		if (pos.f == cur.f)
			sel_y = line;

		move(line, 0);

		attr_t attrs = A_NORMAL;
		attrs |= pos.f == cur.f && !atomic_load_lax(&live) ? A_REVERSE : 0;
		attrs |= pos.f == playing ? A_BOLD : 0;
		attr_set(attrs, 0, NULL);

		if (!pos.f->metadata[M_title]) {
			char const *url = pos.f->a.url;
			if (F_URL != pos.f->a.type)
				url = get_metadata(pos.p, pos.f, MX_name, NULL);
			addstr(url);
			for (int curx = getcurx(stdscr); curx < COLS; ++curx)
				addch(' ');
		} else {
			int x = 0;
			for (c = defs; c < endc; ++c) {
				char mbuf[FILE_METADATA_BUFSZ];
				char const *s = get_metadata(pos.p, pos.f, c->mx, mbuf);
				if (!c->mod) {
					if (x) {
						int curx = getcurx(stdscr);
						if (x - 1 < curx) {
							move(line, x - 1);
							addch(' ');
						} else {
							for (; curx < x; ++curx)
								addch(' ');
						}
					}

					x += c->width + 1 /* SP */;
				}

				if (!s)
					continue;

				switch (c->mod) {
				case ' ':
					addch(' ');
					break;

				case ',':
					addch(';');
					break;

				case '+':
					switch (c->m) {
					case M_featured_artist:
					case M_album_featured_artist:
						addstr(" (ft. ");
						break;

					default:
						addstr(" (");
						break;
					}
					break;

				case '-':
					addstr(" - ");
					break;

				case '/':
					addstr(" / ");
					break;
				}

				if (M_title == c->m)
					sel_x = getcurx(stdscr);

				switch (c->m) {
				case M_track:
				case M_disc:
				case M_bpm:
					printw("%*s", c->width, s);
					break;

				case M_length:
				{
					uint64_t n = strtoull(s, NULL, 10);
					printw("%*"PRIu64":%02u",
							c->width - 3 /* :00 */,
							n / 60,
							(unsigned)(n % 60));
				}
					break;

				default:
					addstr(s);
				}

				switch (c->mod) {
				case '+':
					addstr(")");
					break;
				}
			}

			for (int curx = getcurx(stdscr); curx < COLS; ++curx)
				addch(' ');
		}

		++line;
		if (pos.f == end.f)
			break;
		pos = seek_playlist(&master, &pos, 1, SEEK_CUR);
	}

	attr_set(A_NORMAL, 0, NULL);
	for (; line <= win_lines; ++line) {
		move(line, 0);
		addch('~');
		clrtoeol();
	}

#if 0
	fprintf(tty, "%s -> %s"LF,
			source_info.buf[birdlock_rd_acquire(&source_info.lock)],
			sink_info.buf[birdlock_rd_acquire(&sink_info.lock)]);
#endif
	update_title(playing);
}

static void
draw_progress(void)
{
	int64_t clock = atomic_load_lax(&cur_pts);
	int64_t duration = atomic_load_lax(&cur_duration);

#if 0
	if (unlikely(AV_LOG_DEBUG <= av_log_get_level())) {
		uint16_t len = atomic_load_lax(&buffer_tail) - atomic_load_lax(&buffer_head);
		fprintf(tty, " buf:%"PRId64"kB low:%"PRId64"kB usr:%"PRId64"kB max:%"PRId64"kB pkt:%d",
				atomic_load_lax(&buffer_bytes) / 1024,
				atomic_load_lax(&buffer_low) / 1024,
				atomic_load_lax(&buffer_bytes_max) / 1024,
				len ? atomic_load_lax(&buffer_bytes) * (UINT16_MAX + 1) / len / 1024 : -1,
				len);
	}
#endif

	int y = LINES - 1;

	move(y, 0);

	attr_set(atomic_load_lax(&live) ? A_REVERSE : A_NORMAL, 0, NULL);
	printw("%4"PRId64, cur_number[live]);
	addch(seek_cmd);
	addch(atomic_load_lax(&paused) ? '.' : '>');

	attr_set(A_NORMAL, 0, NULL);
	printw(
			"%3"PRId64":%02u"
			" / "
			"%3"PRId64":%02u"
			" (%3u%%)"
			" [Track: %u/%u]"
			" [Vol: %3d%%]",
			clock / 60, (unsigned)(clock % 60),
			duration / 60, (unsigned)(duration % 60),
			duration ? (unsigned)(clock * 100 / duration) : 0,
			atomic_load_lax(&cur_track) + 1,
			atomic_load_lax(&in0.nb_audios),
			atomic_load_lax(&volume));

	addstr(" [");
	int x = getcurx(stdscr);
	clrtoeol();

	int l = duration ? clock * (COLS - 1 - x) / duration : 0;
	for (int i = 0; i < l - 1; ++i)
		addch('=');
	if (l)
		addch('>');
	move(y, COLS - 1);
	addch(']');
}

static void
handle_sigwinch(int sig)
{
	(void)sig;

	struct winsize w;
	if (!ioctl(fileno(tty), TIOCGWINSZ, &w)) {
		resize_term(w.ws_row, w.ws_col);
		do_key(CONTROL('L'));
	}
}

static void
handle_sigcont(int sig)
{
	(void)sig;
	do_key(CONTROL('L'));
}

static void
handle_sigexit(int sig)
{
	(void)sig;
	exit(EXIT_SUCCESS);
}

static void
handle_signotify(int sig)
{
	(void)sig;
	enum Event got_events = atomic_exchange_lax(&pending_events, 0);

	if (EVENT_EOF_REACHED & got_events) {
		int old_live = live;
		live = 1;
		do_key(CONTROL('M'));
		live = old_live;
	}

	if ((EVENT_FILE_CHANGED | EVENT_STATE_CHANGED) & got_events) {
		if (EVENT_FILE_CHANGED & got_events)
			draw_files();

		if ((EVENT_FILE_CHANGED | EVENT_STATE_CHANGED) & got_events)
			draw_progress();

		draw_cursor();
		refresh();
	}
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");

	if (!(tty = fopen(ctermid(NULL), "w+e"))) {
		fprintf(stderr, "Could not connect to TTY\n");
		exit(EXIT_FAILURE);
	}
	xassert(0 <= setvbuf(tty, NULL, _IONBF, 0));

	snprintf(msg_path, sizeof msg_path,
			"%s/muck.txt",
			getenv("XDG_RUNTIME_DIR"));
	if (!(fmsg = fopen(msg_path, "ae"))) {
		fprintf(stderr, "Could not open messages file\n");
		exit(EXIT_FAILURE);
	}
	xassert(0 <= setvbuf(fmsg, NULL, _IOLBF, 0));

	atexit(bye);

	main_thread = pthread_self();

	{
		size_t error_offset;
		int error_code;
		re_ucase = pcre2_compile(
			(uint8_t const[]){ "\\p{Lu}" }, 6,
			PCRE2_UTF | PCRE2_NO_UTF_CHECK,
			&error_code, &error_offset,
			NULL);
		xassert(re_ucase);
	}

	/* Setup signals. */
	{
		struct sigaction sa;
		sa.sa_flags = SA_RESTART;
		/* Block all signals. */
		xassert(!sigfillset(&sa.sa_mask));
		xassert(!pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL));

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

		sa.sa_handler = handle_signotify;
		xassert(!sigaction(SIGRTMIN, &sa, NULL));
	}

	/* Setup FFmpeg. */
	av_log_set_callback(log_cb);
	av_log_set_level(AV_LOG_ERROR);

	avdevice_register_all();

	/* Sanitize environment. */
	{
		char const *env;

		if ((env = getenv("MUCK_HOME"))) {
			snprintf(config_home, sizeof config_home, "%s", env);
		} else {
			if ((env = getenv("XDG_CONFIG_HOME"))) {
				snprintf(config_home, sizeof config_home,
						"%s/muck", env);
			} else {
				env = getenv("HOME");
				snprintf(config_home, sizeof config_home,
						"%s/.config/muck", env);
				if (access(config_home, F_OK))
					snprintf(config_home, sizeof config_home,
							"%s/.muck", env);
			}
			xassert(!setenv("MUCK_HOME", config_home, 1));
		}

		if ((env = getenv("MUCK_COVER"))) {
			snprintf(cover_path, sizeof cover_path, "%s", env);
		} else {
			if ((env = getenv("XDG_RUNTIME_DIR"))) {
				snprintf(cover_path, sizeof cover_path,
						"%s/muck-cover", env);
			} else {
				if (!(env = getenv("TMPDIR")))
					env = "/tmp";
				snprintf(cover_path, sizeof cover_path,
						"%s/muck-%ld-cover", env, (long)getuid());
			}

			xassert(!setenv("MUCK_COVER", cover_path, 1));
		}
	}

	xassert(0 <= rnd_init(&rnd));

	/* Set defaults. */
	update_input_info();
	update_output_info();

	/* Setup ended, can load files now. */
	char const *startup_cmd = NULL;
	for (int c; 0 <= (c = getopt(argc, argv, "q:e:a:c:f:n:m:C:dv"));)
		switch (c) {
		case 'q':
			search_history[0] = strdup(optarg);
			break;

		case 'e':
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

		case 'C':
			column_spec = optarg;
			break;

		case 'd':
			av_log_set_level(av_log_get_level() < AV_LOG_DEBUG ? AV_LOG_DEBUG : AV_LOG_TRACE);
			break;

		case 'v':
			puts(MUCK_VERSION);
			exit(EXIT_SUCCESS);

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
			print_strerror("Could not create worker thread");
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
			Playlist *playlist;
			if (!isatty(STDIN_FILENO)) {
				playlist = append_file(&master, F_PLAYLIST);
				init_file(&playlist->a, "stdin");
				playlist->read_only = 1;
				playlist->dirfd = AT_FDCWD;
				read_playlist(playlist, dup(STDIN_FILENO));
			} else {
				playlist = append_file(&master, F_PLAYLIST_DIRECTORY);
				init_file(&playlist->a, ".");
				read_file(&master, &playlist->a);
			}
		} else for (; optind < argc; ++optind) {
			char const *url = argv[optind];
			enum FileType type = probe_url(&master, url);
			AnyFile *a = append_file(&master, type);
			init_file(a, url);
			read_file(&master, a);
		}
	}

	if (search_history[0])
		search_file(search_history[0]);

	if (startup_cmd)
		do_keys(startup_cmd);
	else
		play_file(seek_playlist(&master, NULL, 0, SEEK_SET).f, AV_NOPTS_VALUE);

	/* TUI event loop. */
	{
		pthread_setname_np(pthread_self(), "muck/tty");
		newterm(NULL, stderr, tty);
		start_color();
		use_default_colors();
		cbreak();
		noecho();
		nonl();
		nodelay(stdscr, TRUE);
		keypad(stdscr, TRUE);
		meta(stdscr, TRUE);
		curs_set(0);

		define_key("\033[I", KEY_FOCUS_IN);
		define_key("\033[O", KEY_FOCUS_OUT);
		fputs(SEND_FOCUS_EVENTS, tty);

		struct pollfd pollfd;
		pollfd.fd = fileno(tty);
		pollfd.events = POLLIN;

		sigset_t sigmask;
		xassert(!sigemptyset(&sigmask));

		for (;;) {
			int rc = ppoll(&pollfd, 1, NULL, &sigmask);
			if (rc <= 0 && EINTR == errno)
				continue;
			if (rc <= 0 || (~POLLIN & pollfd.revents))
				exit(EXIT_SUCCESS);

			for (int key; ERR != (key = getch());)
				do_key(key);
		}
	}
}
