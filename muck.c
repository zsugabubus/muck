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

#include "birdlock.h"
#include "rnd.h"

#include "config.h"

#if WITH_ICU
# include <unicode/ucol.h>
# include <unicode/parseerr.h>
#endif

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

#define FFCLAMP(min, x, max) FFMAX(min, FFMIN(x, max))

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
#define atomic_fetch_xor_lax(...) atomic_fetch_xor_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_load_lax(...) atomic_load_explicit(__VA_ARGS__, memory_order_relaxed)
#define atomic_store_lax(...) atomic_store_explicit(__VA_ARGS__, memory_order_relaxed)

#define ssprintf(buf, format, ...) \
	((int)sizeof buf <= snprintf(buf, sizeof buf, format, __VA_ARGS__) ? -1 : 0)

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
	xmacro('O', cover_codec, 10, 0) \
	xmacro('m', mtime, 10, 0) \
	xmacro('l', length, 6, 0) \
	xmacro('z', comment, 20, 0)

/* Extra metadata-like stuff. */
#define METADATAX \
	xmacro('i', index, 0, 0) \
	xmacro('k', visual_index, 0, 0) \
	xmacro('u', name, 30, 1) \
	xmacro('U', url, 50, 1) \
	xmacro('p', playlist, 15, 0)

#define METADATA_ALL METADATA METADATAX

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

/* Adding +1 is safe because we have MX_NB so it will not overflow. */
static enum MetadataX const METADATA_LUT[UINT8_MAX + 1] = {
#define xmacro(letter, name, ...) [letter] = 1 /* Heck. */ + M_##name,
	METADATA
#undef xmacro
#define xmacro(letter, name, ...) [letter] = 1 /* Heck. */ + MX_##name,
	METADATAX
#undef xmacro
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

enum {
	FILE_METADATA_BUFSZ = 20,
};

enum FilterIndex {
	FILTER_ALL,
	FILTER_FILES,
	FILTER_PLAYLISTS,
	FILTER_CUSTOM_0,
};

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
	char *url; /* URL "\0" [METADATA-VALUE [";" METADATA-VALUE]... "\0"]... */
	enum FileType type: CHAR_BIT;
	uint8_t filter_mask; /* (1 << FilterIndex) | ... */
	int16_t playlist_index; /* Parent: playlists[playlist_index]. */
	int32_t playlist_order; /* Order inside playlists. */
	int32_t index[2]; /* files[x->index[live]] == x */
	int32_t order[2]; /* Order without considering filters. */
	uint16_t metadata[M_NB]; /* x => url + metadata[x]; 0 if key not present. */
} File;

typedef struct Playlist Playlist;
struct Playlist {
	File const *f;
	char *name;
	int dirfd;
	char *dirname;
	int16_t index;
	/* Protect user data from unwanted modifications. */
	unsigned read_only: 1;
	unsigned modified: 1;
	int32_t nfiles;
};

/* NOTE: ZARY (NULL) is a special 0-ary expression that always evalutes to
 * true. */

typedef struct Expr Expr;

typedef struct {
	Expr *expr;
} UnaryExpr;

typedef struct {
	Expr *lhs;
	Expr *rhs;
} BinaryExpr;

typedef struct {
	uint64_t keys;
	enum KeyOp {
		OP_RE = 1 << 0,
		OP_LT = 1 << 1,
		OP_EQ = 1 << 2,
		OP_GT = 1 << 3,
		OP_ISSET = 1 << 4,
	} op;
	union {
		pcre2_code *re;
		struct {
			uint8_t nnums;
			int32_t nums[5];
		};
	};
} KVExpr;

struct Expr {
	enum ExprType {
		T_NEG,
		T_AND,
		T_OR,
		T_KV,
	} type;
	union {
		UnaryExpr un;
		BinaryExpr bi;
		KVExpr kv;
	};
};

typedef struct {
	char const *src;
	char const *ptr;
	File *cur;
	pcre2_match_data *match_data;
	char const *error_msg;
	char error_buf[256];
} ExprParserContext;

typedef struct {
	File const *f;
	pcre2_match_data *match_data;
} ExprEvalContext;

typedef struct {
	Expr *query;
	uint8_t filter_index;
} MatchFileContext;

typedef struct {
	AVFormatContext *format_ctx;
	AVCodecContext *codec_ctx;
	AVStream *audio;
} Stream;

#define SEEK_EVENT_INITIALIZER { \
	.dirfd = -1, \
	.whence = SEEK_CUR, \
	.ts = 0, \
}

typedef struct {
	File *f;
	int dirfd;
	char *url;
	enum FileType type;
	unsigned track;
	int whence;
	int64_t ts;
} SeekEvent;

#define METADATA_EVENT_INITIALIZER { 0 }

typedef struct {
	File *f;
	int icy;
	char const *codec_name;
	int sample_rate;
	int channels;
	uint64_t channel_layout;
	enum AVCodecID cover_codec_id;
	int cover_width;
	AVDictionary *metadata;
	int64_t duration;
	time_t mtime;
} MetadataEvent;

#define INPUT_INITIALIZER { \
	.fd = -1, \
	.seek_event = { \
		SEEK_EVENT_INITIALIZER, \
		SEEK_EVENT_INITIALIZER, \
	}, \
	.metadata_event = { \
		METADATA_EVENT_INITIALIZER, \
		METADATA_EVENT_INITIALIZER, \
	}, \
}

typedef struct {
	Stream s;
	AVStream *cover_front;
	int fd;
	unsigned ntracks;
	File *f; /* File source of events. */

	/* All other file references must be treated opaque. Only this single
	 * reference is maintaned by the outside world and ensured that is
	 * surely alive. */
	File *seek_f;

	SeekEvent seek_event[2];
	BirdLock seek_lock;
	MetadataEvent metadata_event[2];
	BirdLock metadata_lock;
} Input;

enum Event {
	EVENT_FILE_CHANGED = 1 << 0,
	EVENT_STATE_CHANGED = 1 << 1,
	EVENT_METADATA_CHANGED = 1 << 2,
	EVENT_EOF_REACHED = 1 << 3,
};

typedef struct Task Task;
typedef struct {
	Task *task;
	int32_t cur;
	int32_t end;
	pthread_t thread;
	void const *arg;
} TaskWorker;

struct Task {
	pthread_mutex_t mutex;
	int32_t cur;
	int32_t remaining;
	int32_t batch_size;
	uint8_t nworkers;
	int (*routine)(TaskWorker *, void const *);
	TaskWorker workers[64];
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
static atomic_uchar ALIGNED_ATOMIC dump_in0;

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

static int32_t nfiles[8];
static File **files;
static int16_t nplaylists;
static Playlist **playlists;

/* TODO: Queue is live queue has p=^queue$ filter. In non-live mode we can select tracks etc. */
static int live = 1;
/**
 * .[live] is the currently used filter.
 */
static uint8_t cur_filter[2] = {
	FILTER_FILES,
	FILTER_FILES,
};
static Expr *filter_exprs[8];

static char *search_history[10];

static char const DEFAULT_SORT_SPEC[] = "";

static char const *column_spec = "iy30a,x25A+Fd*20Tn*40t+f+vlgbIB*LCoOm*z";
static char *sort_spec[2] = {
	(char *)DEFAULT_SORT_SPEC,
	(char *)DEFAULT_SORT_SPEC,
};
static int sort_has_order[2];
static int sort_pending[2] = { 1, 1, };
#if WITH_ICU
static UCollator *sort_ucol;
#endif

static FILE *tty;
static atomic_uchar ALIGNED_ATOMIC focused = 1;
static int32_t top;
static int32_t left;
static int32_t sel = -1;
static int sel_y, sel_x;
static char number_cmd[2];
static int32_t cur_number[2];
static int widen;
static atomic_uchar show_stream;
static unsigned cur_track;
static char seek_cmd = 'n';
static RndState rnd;

static char info_msg[2][128];
static uint8_t info_rd;
static BirdLock info_msg_lock;

static char config_home[PATH_MAX];
static char cover_path[PATH_MAX];

static pcre2_code *re_ucase;
static pcre2_match_data *re_match_data;

static atomic_uchar ALIGNED_ATOMIC pending_events;

static void
notify_event(enum Event event)
{
	if (!atomic_fetch_or_lax(&pending_events, event))
		xassert(!pthread_kill(main_thread, SIGRTMIN));
}

static void
print_error(char const *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	flockfile(stderr);
	fputs("\033[1;31m", stderr);
	vfprintf(stderr, msg, ap);
	fputs("\033[m\n", stderr);
	funlockfile(stderr);
	va_end(ap);
}

static void
notify_msg(char const *format, ...)
{
	char *buf = info_msg[
		birdlock_wr_acquire(&info_msg_lock)
	];

	va_list ap;
	va_start(ap, format);
	vsnprintf(buf, sizeof info_msg[0], format, ap);
	va_end(ap);

	birdlock_wr_release(&info_msg_lock);

	notify_event(EVENT_STATE_CHANGED);
}

static void
notify_strerror(char const *msg)
{
	notify_msg("%s: %s", msg, strerror(errno));
}

static void
notify_strerror_oom(void)
{
	notify_strerror("Cannot allocate memory");
}

static void
notify_oom(void)
{
	errno = ENOMEM;
	notify_strerror_oom();
}

static void
notify_averror(char const *msg, int err)
{
	char error_buf[AV_ERROR_MAX_STRING_SIZE];
	av_make_error_string(error_buf, sizeof error_buf, err);
	notify_msg("%s: %s", msg, error_buf);
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
	char linkname[50];
	sprintf(linkname, "/proc/self/fd/%d", fd);
	ssize_t rc = readlink(linkname, dirbuf, PATH_MAX - 2);
	if (rc < 0)
		strcpy(dirbuf, "(error)");
}

static void
plumb_file(File const *f, uint8_t filter_index, FILE *stream)
{
	if (!(f->filter_mask & (UINT8_C(1) << filter_index)))
		return;

	Playlist *playlist = playlists[f->playlist_index];
	if (F_FILE == f->type &&
	    '/' != *f->url)
	{
		fputs(playlist->dirname, stream);
		fputc('/', stream);
	}
	fputs(f->url, stream);

	for (enum Metadata i = 0; i < M_NB; ++i) {
		fputc('\t', stream);
		if (f->metadata[i])
			fputs(f->url + f->metadata[i], stream);
	}

	fputc('\n', stream);
}

static void sort_files(void);

static void
plumb_files(FILE *stream)
{
	sort_files();

	fputs("path", stream);
	for (enum Metadata i = 0; i < M_NB; ++i) {
		fputc('\t', stream);
		fputs(METADATA_NAMES[i], stream);
	}
	fputc('\n', stream);

	int32_t filter_index = cur_filter[live];
	int32_t n = nfiles[filter_index];
	for (int32_t i = 0; i < n; ++i)
		plumb_file(files[i], filter_index, stream);
}

static int
ensure_size1(void *pp, int32_t nmemb, int32_t size)
{
	if (!((nmemb + 1) & nmemb)) {
		void *p = realloc(*(void **)pp, ((nmemb + 1) * 2 - 1) * size);
		if (!p) {
			notify_strerror_oom();
			return -ENOMEM;
		}
		*(void **)pp = p;
	}

	return 0;
}

static File *
append_file(Playlist *parent, enum FileType type, size_t url_size)
{
	if (ensure_size1(&files, nfiles[FILTER_ALL], sizeof *files))
		return NULL;

	File *f = malloc(sizeof *f);
	char *url = malloc(url_size);
	if (!f || !url) {
		notify_strerror_oom();
		free(f);
		free(url);
		return NULL;
	}
	int32_t i = nfiles[FILTER_ALL];
	files[nfiles[FILTER_ALL]++] = f;
	++nfiles[type <= F_FILE ? FILTER_FILES : FILTER_PLAYLISTS];

	*f = (File){
		.url = url,
		.type = type,
		.filter_mask =
			(UINT8_C(1) << FILTER_ALL) |
			(UINT8_C(1) << (type <= F_FILE ? FILTER_FILES : FILTER_PLAYLISTS)),
		.playlist_index = parent->index,
		.playlist_order = parent->nfiles++,
		.index = { i, i, },
	};

	sort_has_order[0] = 0;
	sort_has_order[1] = 0;
	sort_pending[0] = 1;
	sort_pending[1] = 1;

	return f;
}

static File *
append_file_dupurl(Playlist *parent, enum FileType type, char const *url)
{
	size_t sz = strlen(url) + 1 /* NUL */;
	File *f = append_file(parent, type, sz);
	if (f)
		memcpy(f->url, url, sz);
	return f;
}

static Playlist *
append_playlist(File const *f, char const *name)
{
	assert(!f || F_FILE < f->type);

	if (ensure_size1(&playlists, nplaylists, sizeof *playlists))
		return NULL;

	Playlist *playlist = malloc(sizeof *playlist);
	char *s = strdup(name);
	if (!playlist || !s) {
		notify_strerror_oom();
		free(playlist);
		free(s);
		return NULL;
	}

	*playlist = (Playlist){
		.f = f,
		.name = s,
		.dirfd = -1,
		.index = nplaylists,
	};

	playlists[nplaylists++] = playlist;

	return playlist;
}

static void
print_playlist_error(Playlist const *playlist, int color, char const *msg, size_t lnum, size_t col)
{
	flockfile(stderr);
	fprintf(stderr, "\033[1;%dm", color);
	fputs(playlist->name, stderr);
	fputs(":", stderr);
	if (lnum) {
		fprintf(stderr, "%zu:", lnum);
		if (col)
			fprintf(stderr, "%zu:", col);
	}
	fprintf(stderr, " %s\033[m\n", msg);
	funlockfile(stderr);
}

static void
read_file(File *f);

static void
read_playlist_m3u(Playlist *playlist, int fd)
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
				error_msg = "Cannot read playlist stream";
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
				if (0 < playlist->nfiles) {
				fail_used_too_late:
					error_msg = "Directive may only be used before media URLs";
					goto out;
				}

				Playlist *parent = playlists[playlist->f->playlist_index];

				close(playlist->dirfd);
				playlist->dirfd = openat(
						parent->dirfd,
						col,
						O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);

				/* NOTE: Only plain directory base URLs are supported. */
				if (playlist->dirfd < 0) {
					error_msg = "Cannot open directory of playlist";
					goto out;
				}
			} else if (IS_DIRECTIVE("PLAYLIST:")) {
				if (0 < playlist->nfiles)
					goto fail_used_too_late;

				free(playlist->name);
				if (!(playlist->name = strdup(col))) {
				fail_enomem:
					error_msg = "Cannot allocate memory";
					goto out;
				}
			} else {
				print_playlist_error(playlist, 0, "Unknown comment", lnum, 0);
				playlist->read_only = 1;
			}

#undef IS_DIRECTIVE
		} else if (*line) {
			char const *url = line;
			size_t url_size = line_end - line + 1 /* NUL */;

			if (sizeof fdata < url_size + fdata_size)
				goto fail_too_long;

			enum FileType type = probe_url(NULL, url);
			File *f = append_file(playlist, type, url_size + fdata_size);
			if (!f)
				goto fail_enomem;

			for (enum Metadata i = 0; i < M_NB; ++i)
				f->metadata[i] = UINT16_MAX != file.metadata[i]
					? url_size + file.metadata[i]
					: 0;

			memcpy(f->url, url, url_size);
			memcpy(f->url + url_size, fdata, fdata_size);

			read_file(f);
			RESET_FDATA;
		}

		++line_end; /* Skip LF. */
		buf_size -= line_end - line;
		line = line_end;
		++lnum;
	}

	char dirbuf[PATH_MAX];
	fd2dirname(playlist->dirfd, dirbuf);
	playlist->dirname = strdup(dirbuf);

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
read_playlist_dir(Playlist *playlist, int fd)
{
	playlist->dirfd = fd;
	playlist->dirname = strdup(playlist->f->url);
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
		File *f = append_file_dupurl(playlist, type, name);
		read_file(f);
	}

	closedir(dir);
}

static void
reap(pid_t pid)
{
	int status;
	xassert(0 <= waitpid(pid, &status, 0));

	if (!(WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status)))
		notify_msg("Child process terminated with failure");
}

static void
compress_playlist(Playlist *playlist, int *playlist_fd, pid_t *pid, int do_compress)
{
	int pipes[2] = { -1, -1 };

	(void)pipe2(pipes, O_CLOEXEC);

	if ((*pid = fork()) < 0) {
		notify_msg("Cannot %s playlist: %s",
				do_compress ? "compress" : "decompress",
				playlist->name);
	} else if (!*pid) {
		char const *program = probe_compressor(playlist->f->url);

		if (dup2(do_compress ? pipes[0] : *playlist_fd, STDIN_FILENO) < 0 ||
		    dup2(do_compress ? *playlist_fd : pipes[1], STDOUT_FILENO) < 0 ||
		    execlp(program, program, "-c", do_compress ? NULL : "-d", NULL) < 0)
			/* :( */(void)0;
		_exit(EXIT_FAILURE);
	}

	close(pipes[!do_compress]);
	close(*playlist_fd);
	*playlist_fd = pipes[do_compress];
}

static void
read_playlist(Playlist *playlist, int fd)
{
	switch (playlist->f->type) {
	case F_PLAYLIST:
	case F_PLAYLIST_COMPRESSED:
	{
		char *slash = strrchr(playlist->f->url, '/');
		if (slash)
			*slash = '\0';

		char const *dirname = slash ? playlist->f->url : ".";

		Playlist *parent = playlists[playlist->f->playlist_index];
		playlist->dirfd = openat(parent->dirfd, dirname,
				O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);
		if (playlist->dirfd < 0)
			return;

		if (slash)
			*slash = '/';

		pid_t pid = -1;
		if (F_PLAYLIST_COMPRESSED == playlist->f->type)
			compress_playlist(playlist, &fd, &pid, 0);

		read_playlist_m3u(playlist, fd);

		if (0 <= pid)
			reap(pid);
	}
		break;

	case F_PLAYLIST_DIRECTORY:
		read_playlist_dir(playlist, fd);
		break;

	default:
		abort();
	}
}

static void
read_file(File *f)
{
	if (f->type <= F_FILE)
		return;

	Playlist *parent = playlists[f->playlist_index];
	int fd = openat(parent->dirfd, f->url, O_CLOEXEC | O_RDONLY);
	if (fd < 0) {
		notify_msg("Cannot open '%s': %s", f->url, strerror(errno));
		return;
	}

	Playlist *playlist = append_playlist(f, f->url);
	if (!playlist) {
		close(fd);
		return;
	}

	read_playlist(playlist, fd);
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
						? f->url + f->metadata[M_length]
						: "");

		fprintf(stream, " %s=\"", METADATA_NAMES[i]);
		for (char const *c = f->url + f->metadata[i]; *c; ++c) {
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

	for (int32_t i = 0; i < nfiles[FILTER_ALL]; ++i) {
		File const *f = files[i];
		if (playlist->index != f->playlist_index)
			continue;

		if (f->type <= F_FILE)
			write_file(f, stream);
		fprintf(stream, "%s\n", f->url);
	}
}

static void
save_playlist(Playlist *playlist)
{
	if (playlist->read_only ||
	    !playlist->modified)
		return;

	char const *error_msg = NULL;
	char tmp[PATH_MAX];
	*tmp = '\0';
	int fd = -1;
	FILE *stream = NULL;
	pid_t pid = -1;

	int dirfd = playlists[playlist->f->playlist_index]->dirfd;
	if (ssprintf(tmp, "%s~", playlist->f->url) < 0 ||
	    (fd = openat(dirfd, tmp, O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, 0666)) < 0)
	{
		error_msg = "Cannot open temporary playlist file";
		return;
	}

	if (F_PLAYLIST_COMPRESSED == playlist->f->type)
		compress_playlist(playlist, &fd, &pid, 1);

	stream = fdopen(fd, "w");
	if (!stream) {
		error_msg = "Cannot open playlist stream";
		goto out;
	}
	fd = -1;

	char buf[UINT16_MAX + 1];
	setbuffer(stream, buf, sizeof buf);

	write_playlist(playlist, stream);

	if (fflush(stream), ferror(stream)) {
		error_msg = "Cannot write playlist";
		goto out;
	}

	fclose(stream);
	stream = NULL;

	if (0 <= pid) {
		reap(pid);
		pid = -1;
	}

	if (renameat(dirfd, tmp, dirfd, playlist->f->url) < 0) {
		error_msg = "Cannot rename playlist";
		goto out;
	}
	*tmp = '\0';

	playlist->modified = 0;

out:
	if (error_msg)
		notify_msg("Cannot save playlist: %s: %s", playlist->name, error_msg);

	if (*tmp)
		unlink(tmp);

	if (0 <= fd)
		close(fd);

	if (stream)
		fclose(stream);

	if (0 <= pid)
		reap(pid);
}

static void
close_output(void)
{
	if (out.format_ctx) {
		int rc = av_write_trailer(out.format_ctx);
		if (rc < 0)
			notify_averror("Cannot close output", rc);
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
	size_t rem = UINT16_MAX - *fdata_size;
	int n = vsnprintf(fdata + *fdata_size, rem, format, ap);
	va_end(ap);

	if (rem <= (size_t)n)
		return -1;
	if (!n)
		return 0;

	tmpf->metadata[m] = *fdata_size;
	*fdata_size += n + 1 /* NUL */;

	return 0;
}

static int
fdata_write_basic(MetadataEvent const *e, File *tmpf, char *fdata, size_t *fdata_size)
{
	char buf[128];
	int rc;
	av_get_channel_layout_string(buf, sizeof buf,
			e->channels,
			e->channel_layout);
	rc = fdata_writef(tmpf, fdata, fdata_size, M_codec,
			"%s-%s-%d",
			e->codec_name,
			buf,
			e->sample_rate / 1000);
	if (rc < 0)
		return rc;

	if (e->cover_codec_id) {
		rc = fdata_writef(tmpf, fdata, fdata_size, M_cover_codec,
				"%s-%d",
				avcodec_get_name(e->cover_codec_id),
				e->cover_width);
		if (rc < 0)
			return rc;
	}

	/* Preserve. */
	if (e->f->metadata[M_comment]) {
		int rc = fdata_writef(tmpf, fdata, fdata_size, M_comment,
				"%s", e->f->url + e->f->metadata[M_comment]);
		if (rc < 0)
			return rc;
	}

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

static int
read_stream_metadata(MetadataEvent const *e)
{
	AVDictionary const *m = e->metadata;
	File *f = e->f;
	Playlist *playlist = playlists[f->playlist_index];
	File tmpf;
	char fdata[UINT16_MAX];

	size_t url_size = strlen(f->url) + 1 /* NUL */;
	size_t fdata_size = url_size;

	for (enum Metadata i = 0; i < M_NB; ++i)
		tmpf.metadata[i] = 0;

	AVDictionaryEntry const *t;
	AVDictionaryEntry const *t2;

	/* Should not fail since it has been already stored. */
	xassert(0 <= fdata_write_basic(e, &tmpf, fdata, &fdata_size));

	t = av_dict_get(m, "icy-name", NULL, 0);
	if (!t || !*t->value)
		t = av_dict_get(m, "icy-url", NULL, 0);

	t2 = av_dict_get(m, "icy-description", NULL, 0);

	(void)fdata_writef(&tmpf, fdata, &fdata_size,
			M_artist, "%s%s%s",
			t && *t->value ? t->value : f->url,
			t2 && *t2->value ? " - " : "",
			t2 && *t2->value ? t2->value : "");

	t = av_dict_get(m, "StreamTitle", NULL, 0);
	if (t)
		(void)fdata_writef(&tmpf, fdata, &fdata_size,
				M_title, "%s", *t->value ? t->value : "ID");

	t = av_dict_get(m, "icy-genre", NULL, 0);
	if (t && *t->value)
		(void)fdata_writef(&tmpf, fdata, &fdata_size,
				M_genre, "%s", t->value);

	void *p = malloc(fdata_size);
	if (!p) {
		notify_strerror_oom();
		return -1;
	}

	playlist->modified = 1;

	memcpy(p, f->url, url_size);
	memcpy(p + url_size, fdata + url_size, fdata_size - url_size);

	free(f->url);
	f->url = p;

	memcpy(f->metadata, tmpf.metadata, sizeof tmpf.metadata);

	return 1;
}

static int
read_metadata(MetadataEvent const *e)
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
		{ M_bpm, "TRACK/BPM\0" "bpm\0" "TBPM\0" },
		{ M_catalog, "ALBUM/CATALOG_NUMBER\0" },
		{ M_date, "ALBUM/DATE_RELEASED\0" "date_released\0" "date\0" "date_published\0" "TYER\0" },
		{ M_disc, "disc\0" },
		{ M_disc_total, "disc_total\0" },
		{ M_featured_artist, "TRACK/FEATURED_ARTIST\0" },
		{ M_genre, "genre\0" },
		{ M_isrc, "TRACK/ISRC\0" "isrc\0" "TSRC\0" },
		{ M_label, "ALBUM/LABEL\0" "label\0" },
		{ M_title, "title\0" "tit1\0" },
		{ M_track, "track\0" },
		{ M_track_total, "track_total\0" },
		{ M_version, "TRACK/VERSION\0" "version\0" },

	};

	AVDictionary const *m = e->metadata;
	File *f = e->f;
	Playlist *playlist = playlists[f->playlist_index];

	File tmpf;
	char fdata[UINT16_MAX];

	/* Begin file data with its URL. */
	size_t url_size = strlen(f->url) + 1 /* NUL */;
	size_t fdata_size = url_size;

	for (enum Metadata i = 0; i < M_NB; ++i)
		tmpf.metadata[i] = 0;

	if (AV_NOPTS_VALUE != e->duration) {
		int rc = fdata_writef(&tmpf, fdata, &fdata_size, M_length,
				"%"PRId64,
				av_rescale(e->duration, 1, AV_TIME_BASE));
		if (rc < 0)
			goto fail_too_long;
	}

	if (e->mtime &&
	    fdata_write_date(&tmpf, fdata, &fdata_size, M_mtime, e->mtime) < 0)
		goto fail_too_long;

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

	if (fdata_write_basic(e, &tmpf, fdata, &fdata_size) < 0)
		goto fail_too_long;

	if (!playlist->modified) {
		for (enum Metadata i = 0; i < M_NB; ++i)
			if (!!tmpf.metadata[i] != !!f->metadata[i] ||
			    (tmpf.metadata[i] &&
			     strcmp(fdata + tmpf.metadata[i], f->url + f->metadata[i])))
				goto changed;
		return 0;
	changed:
	}

	void *p = malloc(fdata_size);
	if (!p) {
		notify_strerror_oom();
		return -1;
	}

	playlist->modified = 1;

	memcpy(p, f->url, url_size);
	memcpy(p + url_size, fdata + url_size, fdata_size - url_size);

	free(f->url);
	f->url = p;

	memcpy(f->metadata, tmpf.metadata, sizeof tmpf.metadata);

	return 1;

fail_too_long:
	notify_msg("Too much metadata");
	return -1;
}

static void
write_cover(Input const *in)
{
	char tmp[PATH_MAX];
	if (ssprintf(tmp, "%s~", cover_path) < 0)
		return;

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

	write(fd, data, data_size);
	close(fd);

	if (rename(tmp, cover_path))
		notify_strerror("Cannot rename cover");
}

static int
xdup2(int oldfd, int *newfd)
{
	if (0 <= *newfd)
		return dup2(oldfd, *newfd);
	else
		return (*newfd = dup(oldfd));
}

static void
update_metadata(Input *in)
{
	MetadataEvent *e = &in->metadata_event[
		birdlock_wr_acquire(&in->metadata_lock)
	];

	e->f = in->f;

	AVCodecContext *codec_ctx = in->s.codec_ctx;
	e->sample_rate = codec_ctx->sample_rate;
	e->codec_name = codec_ctx->codec->name;
	e->channels = codec_ctx->channels;
	e->channel_layout = codec_ctx->channel_layout;

	AVCodecParameters *pars =
		in->cover_front ? in->cover_front->codecpar : NULL;
	e->cover_codec_id = pars ? pars->codec_id : AV_CODEC_ID_NONE;
	assert(e->cover_codec_id || !in->cover_front);
	e->cover_width = pars ? pars->width : 0;

	AVFormatContext *format_ctx = in->s.format_ctx;
	e->duration = format_ctx->duration;
	av_dict_free(&e->metadata);
	e->metadata = format_ctx->metadata;
	format_ctx->metadata = NULL;

	struct stat st;
	if (0 <= in->fd && 0 <= fstat(in->fd, &st))
		e->mtime = st.st_mtime;
	else
		e->mtime = 0;

	birdlock_wr_release(&in->metadata_lock);
	notify_event(EVENT_METADATA_CHANGED);
}

static void
open_input(Input *in, SeekEvent *e)
{
	memset(&in->s, 0, sizeof in->s);

	char const *url;
	char urlbuf[sizeof "pipe:" + 10];

	if (F_URL == e->type) {
		in->fd = -1;
		url = e->url;
	} else {
		in->fd = openat(e->dirfd, e->url, O_CLOEXEC | O_RDONLY);
		if (in->fd < 0) {
			notify_msg("Cannot open '%s': %s", e->url, strerror(errno));
			return;
		}

		sprintf(urlbuf, "pipe:%d", in->fd);
		url = urlbuf;
	}

	int rc;

	rc = avformat_open_input(&in->s.format_ctx, url, NULL, NULL);
	if (rc < 0) {
		char error_buf[AV_ERROR_MAX_STRING_SIZE];
		av_make_error_string(error_buf, sizeof error_buf, rc);
		notify_msg("Cannot open input '%s' ('%s'): %s", url, e->url, error_buf);
		return;
	}

	/* Get information on the input file (number of streams etc.). */
	(void)avformat_find_stream_info(in->s.format_ctx, NULL);

	in->cover_front = NULL;
	in->s.audio = NULL;

	unsigned ntracks = 0;

	for (unsigned i = 0; i < in->s.format_ctx->nb_streams; ++i) {
		AVStream *stream = in->s.format_ctx->streams[i];

		stream->discard = AVDISCARD_ALL;

		if (AVMEDIA_TYPE_AUDIO == stream->codecpar->codec_type) {
			if (e->track == ntracks)
				in->s.audio = stream;
			++ntracks;
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

	atomic_store_lax(&in->ntracks, ntracks);

	if (!in->s.audio) {
		notify_msg("No audio streams found");
		return;
	}

#if 0
	AVStream *default_stream = in->s.format_ctx->streams[av_find_default_stream_index(in->s.format_ctx)];
	if (default_stream->opaque)
		in->s.audio = default_stream;
#endif

	in->s.audio->discard = 0;

	const AVCodec *codec;

	AVCodecParameters const *pars = in->s.audio->codecpar;
	/* Find a decoder for the audio stream. */
	if (!(codec = avcodec_find_decoder(pars->codec_id))) {
		notify_msg("Cannot find %s decoder",
				avcodec_get_name(pars->codec_id));
		return;
	}

	/* Allocate a new decoding context. */
	if (!(in->s.codec_ctx = avcodec_alloc_context3(codec))) {
		notify_msg("Cannot allocate codec");
		return;
	}

	/* Initialize the stream parameters with demuxer information. */
	rc = avcodec_parameters_to_context(in->s.codec_ctx, pars);
	if (rc < 0) {
		notify_averror("Cannot initalize codec parameters", rc);
		return;
	}

	in->s.codec_ctx->time_base = in->s.audio->time_base;

	rc = avcodec_open2(in->s.codec_ctx, codec, NULL);
	if (rc < 0) {
		notify_averror("Cannot open codec", rc);
		return;
	}

	update_metadata(in);
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
		sbprintf(pbuf, pn, ", %"PRId64":%02hu",
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
		error_msg = "Cannot allocate memory";
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
	av_get_channel_layout_string(buf, sizeof buf, 0, out.codec_ctx->channel_layout);
	(void)av_opt_set(format_ctx, "channel_layouts", buf, AV_OPT_SEARCH_CHILDREN);

	(void)av_opt_set(format_ctx, "sample_fmts",
			av_get_sample_fmt_name(out.codec_ctx->sample_fmt),
			AV_OPT_SEARCH_CHILDREN);

	snprintf(buf, sizeof buf, "%d", out.codec_ctx->sample_rate);
	(void)av_opt_set(format_ctx, "sample_rates", buf, AV_OPT_SEARCH_CHILDREN);

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

	rc = avfilter_link(sink_end->filter_ctx, 0, buffersink_ctx, 0);
	if (rc < 0) {
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
		char error_buf[AV_ERROR_MAX_STRING_SIZE];
		av_make_error_string(error_buf, sizeof error_buf, rc);
		notify_msg("%s: %s", error_msg, error_buf);
		ret = -1;
	}

	avfilter_inout_free(&src_end);
	avfilter_inout_free(&sink_end);

	return ret;
}

static void
update_output_info(void)
{
	char *buf = sink_info.buf[
		birdlock_wr_acquire(&sink_info.lock)
	];

	int n = sizeof sink_info.buf[0];
	print_stream(&buf, &n, &out, 1);

	birdlock_wr_release(&sink_info.lock);

	if (atomic_load_lax(&show_stream))
		notify_event(EVENT_STATE_CHANGED);
}

static int
configure_output(AVFrame const *frame)
{
	AVCodec const *codec = !strcmp(ocodec, "pcm")
		? avcodec_find_encoder(av_get_pcm_codec(frame->format, -1))
		: avcodec_find_encoder_by_name(ocodec);
	if (!codec) {
		notify_msg("Cannot find encoder");
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
		notify_averror("Cannot allocate output", rc);
		goto fail;
	}

	if (!(AVFMT_NOFILE & out.format_ctx->oformat->flags)) {
		rc = avio_open(&out.format_ctx->pb, ofilename, AVIO_FLAG_WRITE);
		if (rc < 0) {
			notify_averror("Cannot open output filename", rc);
			goto fail;
		}
	}

	AVStream *stream;
	/* Create a new audio stream in the output file container. */
	if (!(stream = avformat_new_stream(out.format_ctx, NULL))) {
		notify_averror("Cannot allocate output stream", rc);
		goto fail;
	}

	if (!(out.codec_ctx = avcodec_alloc_context3(codec))) {
		notify_averror("Cannot allocate encoder", rc);
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
		notify_averror("Cannot open encoder", rc);
		goto fail;
	}

	rc = avformat_write_header(out.format_ctx, NULL);
	if (rc < 0) {
		notify_averror("Cannot open output", rc);
		goto fail;
	}

	out.audio = out.format_ctx->streams[0];

	update_output_info();

	return 1;

fail:
	close_output();
	return -1;
}

static char const *
get_metadata(File const *f, enum MetadataX m, char buf[FILE_METADATA_BUFSZ])
{
	if (m < (enum MetadataX)M_NB)
		return f->metadata[m] ? f->url + f->metadata[m] : NULL;
	else switch (m) {
	case MX_index:
		sprintf(buf, "%"PRIu32, f->playlist_order);
		return buf;

	case MX_visual_index:
		sprintf(buf, "%"PRIu32, f->index[live]);
		return buf;

	case MX_url:
		return f->url;

	case MX_name:
	{
		char const *p = strrchr(f->url, '/');
		return p && p[1] ? p + 1 : f->url;
	}

	case MX_playlist:
		return playlists[f->playlist_index]->name;

	default:
		abort();
	}
}

static char const *
expr_strtoi(char const *s, int32_t *ret)
{
	while (*s && !('0' <= *s && *s <= '9'))
		++s;
	if (!*s)
		return NULL;

	int32_t n = 0;
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
	char const *value = get_metadata(ctx->f, m, mbuf);

	/* Fallback to the URL if metadata is missing for this
	 * file. This way user can avoid nasty queries in a new
	 * playlist. */
	if (!value &&
	    !(OP_ISSET & expr->kv.op) &&
	    (METADATA_IN_URL & (UINT64_C(1) << m)) &&
	    !ctx->f->metadata[M_length])
		value = ctx->f->url;
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

			int32_t vn;
			if (!(s = expr_strtoi(s, &vn)))
				return 0;

			int32_t n = expr->kv.nums[i++];
			enum KeyOp rel = OP_LT << ((vn > n) - (vn < n) + 1);
			if (rel & ~OP_EQ & expr->kv.op)
				return 1;
			if (rel & ~expr->kv.op)
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
		enum MetadataX m = METADATA_LUT[(uint8_t)*parser->ptr];
		if (!m--) {
			parser->error_msg = "Unknown key";
			goto fail;
		}
		++parser->ptr;

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

	for (; *p && (st ? st != *p : ' ' != *p && '|' != *p && ')' != *p); ++p) {
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
			memcpy(buf + buf_size, "[._ -]", 6);
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

		File const *cur = parser->cur;
		if (!cur) {
			parser->error_msg = "No current file";
			goto fail;
		}

		for (uint64_t mxs = expr->kv.keys; mxs;) {
			enum MetadataX m = __builtin_ctz(mxs);
			mxs ^= UINT64_C(1) << m;

			char mbuf[FILE_METADATA_BUFSZ];
			char const *value = get_metadata(cur, m, mbuf);
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
			if (FF_ARRAY_ELEMS(expr->kv.nums) <= expr->kv.nnums) {
				parser->error_msg = "Too much numbers";
				goto fail;
			}

			if (!(s = expr_strtoi(s, &expr->kv.nums[expr->kv.nnums])))
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
	static uint64_t const METADATA_MASK = ((uint64_t)1 << M_NB) - 1;

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
			return
				1000 * __builtin_popcount(expr->kv.keys & METADATA_MASK) +
				/* Expect extended keys to be more unique. */
				10 * __builtin_popcount(expr->kv.keys & ~METADATA_MASK);
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

static void *
task_worker(void *arg)
{
	TaskWorker *worker = arg;

#if HAVE_PTHREAD_SETNAME_NP
	char name[16];
	snprintf(name, sizeof name, "muck/worker%zu",
			(size_t)(worker - worker->task->workers));
	pthread_setname_np(pthread_self(), name);
#endif

	return (void *)(intptr_t)worker->task->routine(worker, worker->arg);
}

static int
for_each_file_par(int (*routine)(TaskWorker *, void const *), void const *arg)
{
	static int32_t const BATCH_SIZE_MIN = 16;
	static int32_t const BATCH_SIZE_MAX = 256;

	static long ncpus;
	if (!ncpus) {
		ncpus = sysconf(_SC_NPROCESSORS_ONLN);
		ncpus = FFCLAMP(1, ncpus, FF_ARRAY_ELEMS(((Task *)0)->workers));
	}

	Task task;

	xassert(!pthread_mutex_init(&task.mutex, NULL));

	task.remaining = nfiles[FILTER_ALL];
	if (1 < ncpus)
		task.batch_size = FFCLAMP(
				BATCH_SIZE_MIN,
				task.remaining / ncpus,
				BATCH_SIZE_MAX);
	else
		task.batch_size = task.remaining;
	task.cur = 0;

	task.nworkers = (task.remaining + task.batch_size - 1) / task.batch_size;
	task.nworkers = FFMIN(task.nworkers, ncpus);

	int rc;

	task.routine = routine;
	TaskWorker *worker = task.workers;
	for (;;) {
		*worker = (TaskWorker){
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
		xassert(!pthread_join(worker->thread, NULL));

	xassert(!pthread_mutex_destroy(&task.mutex));

	return !task.remaining ? 0 : (assert(rc < 0), rc);
}

static File *
worker_get(TaskWorker *worker)
{
	if (unlikely(worker->end <= worker->cur)) {
		Task *task = worker->task;

		if (unlikely(!task->remaining))
			return 0;

		xassert(!pthread_mutex_lock(&task->mutex));

		int32_t n = FFMIN(task->batch_size, task->remaining);
		worker->cur = task->cur;
		worker->end = task->cur + n;

		task->remaining -= n;
		task->cur = worker->end;

		xassert(!pthread_mutex_unlock(&task->mutex));
	}

	return files[worker->cur++];
}

static int
spawn(void)
{
	fputs(STOP_FOCUS_EVENTS, tty);
	endwin();

	/* Note that all signals are blocked so handlers do not have to be
	 * reset. */

	pid_t pid = fork();
	if (!pid) {
		pthread_setname_np(pthread_self(), "muck/child");
		int tty_fd = fileno(tty);
		xassert(0 <= dup2(tty_fd, STDIN_FILENO));
		xassert(0 <= dup2(tty_fd, STDOUT_FILENO));
		xassert(0 <= dup2(tty_fd, STDERR_FILENO));
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

static int
match_file_worker(TaskWorker *worker, void const *arg)
{
	pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
	if (!match_data)
		return -ENOMEM;

	MatchFileContext const *ctx = arg;
	uint8_t filter_mask = UINT8_C(1) << ctx->filter_index;

	int32_t n = 0;
	for (File *f; (f = worker_get(worker));) {
		/* Hide playlists. */
		if (F_FILE < f->type)
			continue;

		if (expr_eval(ctx->query, &(ExprEvalContext const){
			.f = f,
			.match_data = match_data,
		})) {
			f->filter_mask |= filter_mask;
			++n;
		} else {
			f->filter_mask &= ~filter_mask;
		}
	}

	pcre2_match_data_free(match_data);

	atomic_fetch_add_lax(&nfiles[ctx->filter_index], n);
	return 0;
}

static File *
get_playing(void)
{
	return in0.seek_f;
}

static int32_t const POS_RND = INT32_MIN;

static File *
seek_playlist(int32_t pos, int whence)
{
	sort_files();

	uint8_t filter_index = cur_filter[live];
	int32_t n = nfiles[filter_index];
	if (!n)
		return NULL;

	if (POS_RND == pos)
		pos = rndn(&rnd, n - (SEEK_CUR == whence));

	if (SEEK_SET == whence) {
		/* Noop. */
	} else if (SEEK_END == whence) {
		pos = n - 1 - pos;
	} else if (SEEK_CUR == whence) {
		if (live) {
			File const *playing = get_playing();
			pos +=
				playing &&
				((UINT8_C(1) << filter_index) & playing->filter_mask)
					? playing->index[live]
					: 0;
		} else {
			pos += sel;
		}
	} else {
		abort();
	}

	pos %= n;
	pos += n;
	pos %= n;

	return files[pos];
}

static int
file_order_cmp(void const *px, void const *py)
{
	File const *x = *(File **)px;
	File const *y = *(File **)py;

	return FFDIFFSIGN(x->order[live], y->order[live]);
}

static int
file_cmp(void const *px, void const *py)
{
	File const *x = *(File **)px;
	File const *y = *(File **)py;

	uint8_t filter_mask = UINT8_C(1) << cur_filter[live];
	if (!(x->filter_mask & y->filter_mask & filter_mask))
		return !!(x->filter_mask & filter_mask) - !!(y->filter_mask & filter_mask);

	for (char const *s = sort_spec[live]; *s; ++s) {
		int cmp = 0;

		enum MetadataX m = METADATA_LUT[(uint8_t)*s];
		if (!m--) {
			print_error("invalid sort specifier '%c'", *s);
			break;
		}

		int numeric;
		s += (numeric = '=' == s[1]);
		int neg;
		s += (neg = '-' == s[1]);

		char mbufx[FILE_METADATA_BUFSZ];
		char mbufy[FILE_METADATA_BUFSZ];
		char const *vx = get_metadata(x, m, mbufx);
		char const *vy = get_metadata(y, m, mbufy);

		if (!vx || !vy) {
			cmp = !vy - !vx;
			goto decide;
		}

		if (numeric) {
			char const *px = vx;
			char const *py = vy;
			int any = 0;
			for (;;) {
				int32_t nx, ny;
				px = expr_strtoi(px, &nx);
				py = expr_strtoi(py, &ny);
				if (px && py) {
					any = 1;
					if (nx == ny)
						continue;
					cmp += !!nx - !!ny;
				} else {
					cmp += !!px - !!py;
				}
				break;
			}

			if (any)
				goto decide;
		}

		for (char const *px = vx;;) {
			char *px_end = strchrnul(px, ';');
			size_t nx = px_end - px;

			for (char const *py = vy;;) {
				char *py_end = strchrnul(py, ';');
				size_t ny = py_end - py;

#if WITH_ICU
				/* TODO: Maybe compare without space and
				 * space-like characters. */
				UErrorCode error_code = U_ZERO_ERROR;
				UCollationResult rc = ucol_strcollUTF8(sort_ucol,
						px, nx, py, ny, &error_code);
				assert(U_SUCCESS(error_code));
				int c =
					UCOL_LESS == rc ? -1 :
					UCOL_GREATER == rc ? 1 :
					0;
#else
				size_t n = FFMIN(nx, ny);
				int c = memcmp(px, py, n);
#endif
				if (!c)
					c = FFDIFFSIGN(nx, ny);
				else
					c = FFDIFFSIGN(c, 0);
				cmp += c;

				if (!*py_end)
					break;
				py = py_end + 1;
			}

			if (!*px_end)
				break;
			px = px_end + 1;
		}

	decide:
		if (cmp)
			return neg ? -cmp : cmp;
	}

	return 0;
}

static int
file_ordered(File const *f)
{
	int32_t n = cur_filter[live];
	return
		(!f->index[live] || file_cmp(&files[f->index[live] - 1], &f) <= 0) &&
		(nfiles[n] == f->index[live] + 1 || file_cmp(&f, &files[f->index[live] + 1]) <= 0);
}

static void
load_sort(void)
{
	/* Indices are good. */
	if (sort_pending[live])
		return;

	/* Initialize unused indices. */
	for (int32_t i = nfiles[cur_filter[!live]];
	     i < nfiles[FILTER_ALL]; ++i)
		files[i]->index[!live] = i;

	/* Restore order using saved indices. */
	int32_t n = nfiles[cur_filter[live]];
	for (int32_t i = 0; i < n; ++i)
		for (int32_t to; i != (to = files[i]->index[live]);)
			FFSWAP(File *, files[i], files[to]);
}

static void
sort_files(void)
{
	if (!sort_pending[live])
		return;
	sort_pending[live] = 0;

	uint8_t filter_index = cur_filter[live];
	uint8_t filter_mask = UINT8_C(1) << filter_index;
	int32_t n = nfiles[filter_index];
	File *cur = 0 <= sel ? files[sel] : NULL;

	int32_t k = 0;
	for (int32_t i = 0; i < nfiles[FILTER_ALL] && k < n; ++i)
		if (filter_mask & files[i]->filter_mask) {
			if (k != i)
				FFSWAP(File *, files[k], files[i]);
			++k;
		}

	assert(n == k);

	qsort(files, n, sizeof *files, sort_has_order[live] ? file_order_cmp : file_cmp);

	for (int32_t i = 0; i < n; ++i)
		files[i]->index[live] = i;

	if (cur && (filter_mask & cur->filter_mask))
		sel = cur->index[live];
	else
		sel = FFMIN(FFMAX(0, sel), n - 1);

	if (!sort_has_order[live]) {
		sort_has_order[live] = nfiles[FILTER_ALL] <= n;
		if (sort_has_order[live])
			for (int32_t i = 0; i < n; ++i)
				files[i]->order[live] = i;
	}
}

static Expr *
parse_filter_spec(ExprParserContext *parser, char const *s)
{
	Expr *query = NULL;

	parser->error_msg = NULL;
	parser->cur = get_playing();
	parser->ptr = parser->src = s;
	parser->match_data = re_match_data;

	query = expr_parse(parser);
	if (parser->error_msg)
		goto fail;

	if (!expr_depends_key(query, MX_playlist)) {
		parser->src = parser->ptr = "p~^[^-]";

		Expr *expr = expr_new(T_AND);
		if (!expr) {
			parser->error_msg = strerror(ENOMEM);
			goto fail;
		}
		if (!(expr->bi.rhs = expr_parse(parser))) {
			expr_free(expr);
			goto fail;
		}
		expr->bi.lhs = query;
		query = expr;
	}

	expr_optimize(&query);

	return query;

fail:
	expr_free(query);
	return NULL;
}

static void select_file(File *f);

static void
handle_filter_change(void)
{
	if (!live)
		return;

	File *f = seek_playlist(0, SEEK_CUR);
	File *cur = get_playing();
	if (f && cur && f != cur)
		select_file(f);
}

static void
filter_files(ExprParserContext *parser, char const *s)
{
	Expr *query = parse_filter_spec(parser, s);
	if (!query)
		return;

	cur_filter[live] = FILTER_CUSTOM_0 + live;
	uint8_t filter_index = cur_filter[live];

	expr_free(filter_exprs[filter_index]);
	filter_exprs[filter_index] = query;

	/* TODO: Cache filters. */
	nfiles[filter_index] = 0;
	(void)for_each_file_par(match_file_worker, &(MatchFileContext const){
		.query = query,
		.filter_index = filter_index,
	});

	sort_pending[0] = 1;
	sort_pending[1] = 1;

	notify_event(EVENT_FILE_CHANGED);

	handle_filter_change();
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
do_wakeup(int *cond)
{
	xassert(!pthread_mutex_lock(&buffer_lock));
	*cond = 1;
	xassert(!pthread_cond_broadcast(&buffer_wakeup));
	xassert(!pthread_mutex_unlock(&buffer_lock));
}

static void
wait_wakeup(int *cond)
{
	xassert(!pthread_mutex_lock(&buffer_lock));
	while (!*cond)
		xassert(!pthread_cond_wait(&buffer_wakeup, &buffer_lock));
	*cond = 0;
	xassert(!pthread_mutex_unlock(&buffer_lock));
}

static void
seek_player(int64_t ts, int whence)
{
	SeekEvent *e = &in0.seek_event[
		birdlock_wr_acquire(&in0.seek_lock)
	];

	free(e->url);
	e->url = NULL;
	e->f = NULL;

	if (SEEK_CUR == whence) {
		e->ts += ts;
	} else {
		e->whence = whence;
		e->ts = ts;
	}

	birdlock_wr_release(&in0.seek_lock);
	do_wakeup(&wakeup_source);
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
	char *buf = source_info.buf[
		birdlock_wr_acquire(&source_info.lock)
	];

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

	if (atomic_load_lax(&show_stream))
		notify_event(EVENT_STATE_CHANGED);
}

static void do_key(int c);

static void *
source_worker(void *arg)
{
	(void)arg;

	pthread_setname_np(pthread_self(), "muck/source");

	AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		notify_oom();
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

		if (likely(!birdlock_rd_test(&in0.seek_lock)))
			goto no_event;

		SeekEvent *e = &in0.seek_event[
			birdlock_rd_acquire(&in0.seek_lock)
		];

		if (e->url) {
			close_input(&in0);

			in0.f = e->f;
			open_input(&in0, e);
			write_cover(&in0);
			update_input_info();

			/* Otherwise would be noise. */
			if (!in0.s.codec_ctx)
				goto eof_reached;

			flush_output = S_STALLED != state;
			state = S_RUNNING;
			seek_buffer(INT64_MIN);
		}

		if (likely(in0.s.codec_ctx)) {
			int64_t target_pts = e->ts;
			switch (e->whence) {
			case SEEK_SET:
				/* Noop. */
				break;

			case SEEK_CUR:
				target_pts += atomic_load_lax(&cur_pts);
				break;

			case SEEK_END:
				target_pts += atomic_load_lax(&cur_duration);
				break;

			default:
				abort();
			}
			target_pts = FFCLAMP(0, target_pts, cur_duration);

			e->whence = SEEK_CUR;
			e->ts = 0;

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
				notify_averror("Cannot seek", rc);
		}
	no_event:

		if (unlikely(atomic_load_lax(&dump_in0))) {
			int old_level = av_log_get_level();
			av_log_set_level(AV_LOG_DEBUG); /* <-- Not atomic. */
			if (in0.s.format_ctx)
				av_dump_format(in0.s.format_ctx, 0, "(input)", 0);
			av_log_set_level(old_level);
			/* It is not an exchange. */
			atomic_store_lax(&dump_in0, 0);
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
			eof_reached:;
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
				notify_oom();
				state = S_STOPPED;
				goto wait;
			}
			buffer[buffer_tail] = frame;
		}

		Input *in = &in0;

		rc = av_read_frame(in->s.format_ctx, pkt);
		if (unlikely(state = rc < 0 ? S_STOPPED : S_RUNNING)) {
			if (AVERROR_EOF != rc)
				notify_averror("Cannot read frame", rc);
			goto wait;
		}

		/* Packet from an uninteresting stream. */
		if (unlikely(in->s.audio->index != pkt->stream_index)) {
			av_packet_unref(pkt);
			continue;
		}

		if (unlikely((AVSTREAM_EVENT_FLAG_METADATA_UPDATED & in->s.format_ctx->event_flags))) {
			in->s.format_ctx->event_flags &= ~AVSTREAM_EVENT_FLAG_METADATA_UPDATED;
			/* Metadata may be moved out on open. Update only if
			 * there is something here. */
			if (in->s.format_ctx->metadata)
				update_metadata(in);
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
				do_wakeup(&wakeup_sink);
			}

			notify_progress();
		} else if (AVERROR(EAGAIN) != rc)
			notify_averror("Cannot decode frame", rc);
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
		notify_oom();
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
			do_wakeup(&wakeup_source);
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
					notify_msg("Cannot find 'volume' filter");
				notify_msg("Cannot set volume");
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
			notify_averror("Cannot push frame into filtergraph", rc);

		rc = av_buffersink_get_frame_flags(buffersink_ctx, frame, 0);
		if (unlikely(rc < 0))
			notify_averror("Cannot pull frame from filtergraph", rc);

		/* Send a frame to encode. */
		rc = avcodec_send_frame(out.codec_ctx, frame);
		if (unlikely(rc < 0))
			notify_averror("Cannot encode frame", rc);

		av_frame_unref(frame);

		/* Receive an encoded packet. */
		while (0 <= (rc = avcodec_receive_packet(out.codec_ctx, pkt))) {
			out_dts += pkt->duration;

			rc = av_write_frame(out.format_ctx, pkt);
			if (unlikely(rc < 0))
				notify_averror("Cannot write encoded frame", rc);
			av_packet_unref(pkt);
		}
		if (unlikely(AVERROR(EAGAIN) != rc))
			notify_averror("Cannot receive encoded frame", rc);
	}

terminate:
	av_free(pars);
	av_frame_free(&frame);
	av_packet_free(&pkt);

	return NULL;
}

static int
file_playlist_order_cmp(void const *px, void const *py)
{
	File const *x = *(File **)px;
	File const *y = *(File **)py;

	return FFDIFFSIGN(x->playlist_order, y->playlist_order);
}

static void
save_playlists(void)
{
	qsort(files, nfiles[FILTER_ALL], sizeof *files, file_playlist_order_cmp);

	for (int16_t i = 0; i < nplaylists; ++i) {
		Playlist *playlist = playlists[i];
		save_playlist(playlist);
	}
}

static void
bye(void)
{
	fputs(STOP_FOCUS_EVENTS, tty);
	endwin();

	save_playlists();

#if CONFIG_VALGRIND
	if (threads_inited) {
		atomic_store_lax(&terminate, 1);
		do_wakeup(&wakeup_source);
		do_wakeup(&wakeup_sink);

		xassert(!pthread_join(source_thread, NULL));
		xassert(!pthread_join(sink_thread, NULL));
	}

	xassert(!pthread_mutex_destroy(&buffer_lock));
	xassert(!pthread_cond_destroy(&buffer_wakeup));

	for (int32_t i = 0; i < nfiles[FILTER_ALL]; ++i) {
		File *f = files[i];
		free(f->url);
		free(f);
	}

	for (int16_t i = 0; i < nplaylists; ++i) {
		Playlist *playlist = playlists[i];
		if (0 <= playlist->dirfd)
			close(playlist->dirfd);
		free(playlist->dirname);
		free(playlist->name);
		free(playlist);
	}

	for (int i = 0; i < 2; ++i) {
		SeekEvent *e = &in0.seek_event[i];
		free(e->url);
		if (0 <= e->dirfd)
			close(e->dirfd);
	}

	for (int i = 0; i < 2; ++i) {
		MetadataEvent *e = &in0.metadata_event[i];
		av_dict_free(&e->metadata);
	}

	close_input(&in0);
	close_output();
	close_graph();

	pcre2_code_free(re_ucase);
	pcre2_match_data_free(re_match_data);

#if WITH_ICU
	if (sort_ucol)
		ucol_close(sort_ucol);
#endif

	uint16_t i = 0;
	do
		av_frame_free(&buffer[i]);
	while ((uint16_t)++i);

	for (size_t i = 0; i < FF_ARRAY_ELEMS(search_history); ++i)
		free(search_history[i]);

	for (int i = 0; i < 2; ++i)
		if (DEFAULT_SORT_SPEC != sort_spec[i])
			free(sort_spec[i]);

	for (size_t i = 0; i < FF_ARRAY_ELEMS(filter_exprs); ++i)
		expr_free(filter_exprs[i]);
#endif
}

static void update_title(void);

static void
play_file(File const *f, int64_t ts)
{
	assert(f);

	SeekEvent *e = &in0.seek_event[
		birdlock_wr_acquire(&in0.seek_lock)
	];

	in0.seek_f = (File *)f;
	e->f = (File *)f;

	Playlist *playlist = playlists[f->playlist_index];
	e->type = f->type;
	free(e->url);
	e->url = strdup(f->url);
	e->track = cur_track;
	xdup2(playlist->dirfd, &e->dirfd);
	e->whence = SEEK_SET;
	e->ts = ts;

	birdlock_wr_release(&in0.seek_lock);
	do_wakeup(&wakeup_source);

	update_title();
}

static FILE *
open_tmpfile(char tmpname[PATH_MAX])
{
	char const *tmpdir = getenv("TMPDIR");
	int n = snprintf(tmpname, PATH_MAX, "%s/muckXXXXXX",
			tmpdir ? tmpdir : "/tmp");
	if (PATH_MAX <= n)
		goto fail;

	int fd = mkostemp(tmpname, O_CLOEXEC);
	if (fd < 0)
		goto fail;

	FILE *ret = fdopen(fd, "w");
	if (!ret) {
		close(fd);
		goto fail;
	}

	return ret;

fail:
	notify_strerror("Cannot create temporary file");
	return NULL;
}

static char *
edit_tmpfile(char const *tmpname)
{
	char *ret = NULL;

	int rc = spawn();
	if (!rc) {
		char const *editor = getenv("EDITOR");
		execlp(editor, editor, "--", tmpname, NULL);
		_exit(EXIT_FAILURE);
	} else if (0 < rc) {
		FILE *stream = fopen(tmpname, "re");
		size_t sz = 0;
		ssize_t len;

		if (stream) {
			len = getline(&ret, &sz, stream);
			if (len < 0) {
				free(ret);
				ret = NULL;
			} else if (0 < len && '\n' == ret[len - 1])
				ret[len - 1] = '\0';

			fclose(stream);
		}
	}

	unlink(tmpname);

	return ret;
}

static void
cat_history_file(char const *name, FILE *stream)
{
	char history_path[PATH_MAX];
	int rc = ssprintf(history_path, "%s/%s", config_home, name);

	char const *home = getenv("HOME");
	size_t home_size = strlen(home);
	int tilde = !strncmp(history_path, home, home_size);
	fprintf(stream, "# %s%s:\n",
			tilde ? "~" : "",
			history_path + (tilde ? home_size : 0));

	FILE *history;
	if (0 <= rc) {
		history = fopen(history_path, "re");
	} else {
		errno = ENAMETOOLONG;
		history = NULL;
	}
	if (history) {
		char buf[BUFSIZ];
		size_t buf_size;
		while (0 < (buf_size = fread(buf, 1, sizeof buf, history)))
			fwrite(buf, 1, buf_size, stream);
		fclose(history);
	} else {
		fprintf(stream, "# %s.\n", strerror(errno));
	}
	fputc('\n', stream);
}

static void
print_syntax_help(File const *cur, FILE *stream)
{
	fputs("# Keys:\n", stream);
	for (enum MetadataX i = 0; i < MX_NB; ++i) {
		char mbuf[FILE_METADATA_BUFSZ];
		char const *value = cur ? get_metadata(cur, i, mbuf) : NULL;
		fprintf(stream, "# %c%c=%-*s%s\n",
				METADATA_IN_URL & (UINT64_C(1) << i) ? '+' : ' ',
				METADATA_LETTERS[i],
				value && *value ? (int)sizeof METADATA_NAMES[i] : 0,
				METADATA_NAMES[i],
				value ? value : "");
	}
}

static void
open_visual_search(void)
{
	ExprParserContext parser = { 0 };

reopen:
	char tmpname[PATH_MAX];
	FILE *stream = open_tmpfile(tmpname);
	if (!stream)
		return;

	if (parser.error_msg)
		fprintf(stream, "%*s<ERROR>%s\n"
				"# Error: %s\n\n",
				(int)(parser.ptr - parser.src), parser.src,
				parser.ptr,
				parser.error_msg);

	int any = 0;
	for (size_t i = 0; i < FF_ARRAY_ELEMS(search_history) && search_history[i]; ++i)
	{
		fprintf(stream, "%s\n", search_history[i]);
		any = 1;
	}
	if (!any)
		fputc('\n', stream);
	fputc('\n', stream);

	File *cur = seek_playlist(0, SEEK_CUR);
	if (cur) {
		for (enum MetadataX i = 0; i < MX_NB; ++i) {
			char mbuf[FILE_METADATA_BUFSZ];
			char const *value = get_metadata(cur, i, mbuf);
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

	cat_history_file("search-history", stream);
	print_syntax_help(cur, stream);

	fclose(stream);

	char *line = edit_tmpfile(tmpname);
	if (!line)
		return;

	char *carry = search_history[0];
	search_history[0] = NULL;
	for (size_t i = 1; i < FF_ARRAY_ELEMS(search_history) && carry; ++i) {
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

	filter_files(&parser, search_history[0]);
	if (parser.error_msg)
		goto reopen;
}

static void
open_visual_sort(void)
{
	char tmpname[PATH_MAX];
	FILE *stream = open_tmpfile(tmpname);
	if (!stream)
		return;

	fputs(sort_spec[live], stream);
	fputc('\n', stream);

	fputc('\n', stream);

	cat_history_file("sort-history", stream);

	File *cur = seek_playlist(0, SEEK_CUR);
	print_syntax_help(cur, stream);

	fclose(stream);

	char *line = edit_tmpfile(tmpname);
	if (!line)
		return;

	if (DEFAULT_SORT_SPEC != sort_spec[live])
		free(sort_spec[live]);
	sort_spec[live] = line;

	sort_has_order[live] = 0;
	sort_pending[live] = 1;
}

static void
pause_player(int pause)
{
	atomic_store_lax(&paused, pause);
	if (!pause) {
		do_wakeup(&wakeup_source);
		do_wakeup(&wakeup_sink);
	}
	notify_event(EVENT_STATE_CHANGED);
}

static struct timespec
get_file_mtim(File const *f)
{
	struct stat st;
	Playlist *parent = playlists[f->playlist_index];
	return fstatat(parent->dirfd, f->url, &st, 0)
		? st.st_mtim
		: (struct timespec){ 0 };
}

static void
select_file(File *f)
{
	if (!f)
		return;

	if (live) {
		cur_track = 0;
		play_file(f, AV_NOPTS_VALUE);
	} else {
		sel = f->index[live];
	}
	notify_event(EVENT_FILE_CHANGED);
}

static void
use_number(char c, int32_t def)
{
	if ('0' == number_cmd[live])
		number_cmd[live] = c;
	else if (c != number_cmd[live])
		cur_number[live] = def;
}

static int32_t
get_number(int32_t def)
{
	if ('0' == number_cmd[live])
		return cur_number[live];
	else
		return def;
}

static void
spawn_script(int c)
{
	File const *f = seek_playlist(0, SEEK_CUR);
	if (!f)
		return;

	struct timespec mtim_before = get_file_mtim(f);

	if (!spawn()) {
		Playlist *playlist = playlists[f->playlist_index];
		if (fchdir(playlist->dirfd) < 0) {
			print_error("Cannot change working directory");
			_exit(EXIT_FAILURE);
		}

		if (f) {
			if (F_FILE == f->type)
				setenv("MUCK_PATH", f->url, 0);

			char name[5 + sizeof *METADATA_NAMES] = "MUCK_";

			for (enum MetadataX m = 0; m < MX_NB; ++m) {
				memcpy(name + 5, METADATA_NAMES[m], sizeof *METADATA_NAMES);
				char mbuf[FILE_METADATA_BUFSZ];
				char const *value = get_metadata(f, m, mbuf);
				if (value)
					setenv(name, value, 0);
			}
		}

		char exe[PATH_MAX];
		if (0 <= ssprintf(exe, "%s/%c", config_home, c))
			execl(exe, exe, f->url, NULL);
		print_error("No binding for '%c'", c);

		_exit(EXIT_FAILURE);
	}

	struct timespec mtim_after = get_file_mtim(f);

	if (memcmp(&mtim_before, &mtim_after, sizeof mtim_before))
		play_file(f, atomic_load_lax(&cur_pts));
}

static void
switch_live(int new_live)
{
	if (new_live == live)
		return;
	live = new_live;

	if (!live) {
		File const *cur = get_playing();
		sel = cur ? cur->index[1] : 0;
	}

	/* Keep values on entering visual mode. */
	cur_filter[0] = cur_filter[1];
	cur_number[0] = cur_number[1];
	number_cmd[0] = '\0';
	number_cmd[1] = '\0';

	load_sort();
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

	if (*info_msg[info_rd]) {
		*info_msg[info_rd] = '\0';
		notify_event(EVENT_STATE_CHANGED);
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
		do_wakeup(&wakeup_source);
		break;

	case 'v':
		switch_live(live ^ 1);
		notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);
		break;

	case 't': /* Tracks. */
	{
		unsigned n = atomic_load_lax(&in0.ntracks);
		if (n) {
			cur_track += 1;
			cur_track %= n;
			File *cur = get_playing();
			if (cur)
				play_file(cur, atomic_load_lax(&cur_pts));
		}
	}
		break;

	case '/': /* Search. */
		open_visual_search();
		break;

	case '|':
		if (isatty(fileno(stdout))) {
			char tmpname[PATH_MAX];
			FILE *stream = open_tmpfile(tmpname);
			if (!stream)
				break;

			plumb_files(stream);
			fclose(stream);

			if (!spawn()) {
				char const *editor = getenv("EDITOR");
				execlp(editor, editor, "--", tmpname, NULL);
				_exit(EXIT_FAILURE);
			}

			unlink(tmpname);
		} else {
			plumb_files(stdout);
		}
		break;

	case 'e': /* Edit. */
	{
		if (live) {
			seek_player(1, SEEK_CUR);
			break;
		}

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

		select_file(seek_playlist(POS_RND, SEEK_CUR));
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

		select_file(seek_playlist(cur_number[live] * dir, SEEK_CUR));
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
			select_file(seek_playlist(0, SEEK_SET));
		}
	}
		break;

	case 'G': /* GO TO. */
	case KEY_END:
		if (live) {
			int32_t n = get_number(100 * 3 / 8);
			seek_player(atomic_load_lax(&cur_duration) * n / 100, SEEK_SET);
		} else {
			select_file(seek_playlist(0, SEEK_END));
		}
		break;

	case 'H':
	case KEY_SLEFT:
	case 'L':
	case KEY_SRIGHT:
		left += 'H' == c || KEY_SLEFT == c ? -1 : 1;
		notify_event(EVENT_FILE_CHANGED);
		break;

	case 'h':
	case KEY_LEFT:
	case 'l':
	case KEY_RIGHT:
	{
		int dir = 'h' == c || KEY_LEFT == c ? -1 : 1;
		int32_t n = get_number(5);
		seek_player(n * dir, SEEK_CUR);
	}
		break;

	case 'j':
	case 'k':
	{
		int dir = 'j' == c ? -1 : 1;
		if (live) {
			int32_t n = get_number(FFMAX(atomic_load_lax(&cur_duration) / 16, +5));
			seek_player(n * dir, SEEK_CUR);
		} else {
			select_file(seek_playlist(get_number(1) * -dir, SEEK_CUR));
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

	case 'o':
	case '=':
		open_visual_sort();
		break;

	case 'w':
		widen ^= 1;
		notify_event(EVENT_FILE_CHANGED);
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

		select_file(seek_playlist(n, SEEK_SET));
	}
		break;

	case 'i':
		atomic_fetch_xor_lax(&show_stream, 1);
		notify_event(EVENT_STATE_CHANGED);
		break;

	case '?':
	case KEY_F(1):
		if (!spawn()) {
			execlp("man", "man", "muck.1", NULL);
			notify_strerror("Cannot open manual page");
			_exit(EXIT_FAILURE);
		}
		break;

	case CONTROL('L'):
		clear();
		notify_event(EVENT_FILE_CHANGED | EVENT_STATE_CHANGED);
		break;

	case CONTROL('M'):
		if (0 <= sel) {
			int old_live = live;
			live = 1;
			select_file(files[sel]);
			live = old_live;
		}
		pause_player(0);
		break;

	case 'Z': /* Zzz. */
	case 'q':
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

	flockfile(stderr);
	if (level <= AV_LOG_ERROR)
		fputs("\033[1;31m", stderr);
	vfprintf(stderr, format, ap);
	if (level <= AV_LOG_ERROR)
		fputs("\033[m", stderr);
	funlockfile(stderr);
}

static void
update_title(void)
{
	File const *f = get_playing();

	/* Note that metadata is free from control characters. */
	fputs("\033]0;", tty);
	if (f && f->metadata[M_title]) {
		fputs(f->url + f->metadata[M_title], tty);
		if (f->metadata[M_version])
			fprintf(tty, " (%s)", f->url + f->metadata[M_version]);
	} else if (f) {
		fputs(f->url, tty);
	} else {
		fputs("muck", tty);
	}
	fputc('\a', tty);
}

static void
draw_cursor(void)
{
	move(sel_y, sel_x);
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

	if (left < 0)
		left = 0;

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

		enum MetadataX m = METADATA_LUT[(uint8_t)*end];
		if (!m--)
			break;

		if (s == end) {
			if ((MX_index == m ||
			     MX_visual_index == m) &&
			    nfiles[FILTER_ALL])
				n = ceil(log(nfiles[FILTER_ALL]) / log(10));
			else
				n = METADATA_COLUMN_WIDTHS[m];
		}

		c->mod = mod;
		c->width = n;
		c->mx = m;

		int w = widen && SHORT_WIDTH < c->width;
		for (ColumnDef const *t = defs; w && t < c; ++t)
			w &= t->width <= SHORT_WIDTH;
		if (w)
			c->width = 2 * c->width < COLS ? COLS / 2 + 1 : COLS;

		stars += '*' == c->mod;
		if (iscol)
			totw += c->width + 1 /* SP */;

		s = end + 1;

		if (iscol ? ++nc <= left : nc == left) {
			c = defs;
			totw = 0;
			stars = 0;
			continue;
		}

		if ((&defs)[1] <= ++c)
			break;
	}

	if (nc < left)
		left = nc;

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
	int win_lines = LINES - 2;

	File const *playing = get_playing();
	File const *fsel = seek_playlist(0, SEEK_CUR);
	int32_t fsel_index = fsel ? fsel->index[live] : 0;
	int32_t old_top = top;
	int32_t scrolloff = 5;
	int32_t n = nfiles[cur_filter[live]];

	top = FFMIN(top, fsel_index - scrolloff);
	top = FFMAX(top + win_lines, fsel_index + 1 + scrolloff) - win_lines;
	top = FFMIN(top + win_lines, n) - win_lines;
	top = FFMAX(top, 0);

	int32_t scroll = top - old_top;
	if (scroll && abs(scroll) <= LINES) {
		scrollok(stdscr, TRUE);
		scrl(scroll);
		scrollok(stdscr, FALSE);
	}

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
	for (; line <= win_lines; ++line) {
		int32_t index = top + line - 1;
		if (n <= index)
			break;

		File *cur = files[index];
		if (index == sel)
			sel_y = line;

		move(line, 0);

		attr_t attrs = A_NORMAL;
		attrs |= index == sel && !live ? A_REVERSE : 0;
		attrs |= cur == playing ? A_BOLD : 0;
		attr_set(attrs, 0, NULL);

		if (!cur->metadata[M_title]) {
			char const *url = cur->url;
			if (F_URL != cur->type)
				url = get_metadata(cur, MX_name, NULL);
			addstr(url);
			for (int curx = getcurx(stdscr); curx < COLS; ++curx)
				addch(' ');
		} else {
			int x = 0;
			for (c = defs; c < endc; ++c) {
				char mbuf[FILE_METADATA_BUFSZ];
				char const *s = get_metadata(cur, c->mx, mbuf);
				if (!c->mod) {
					if (x && s) {
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
					uint32_t n = strtoull(s, NULL, 10);
					printw("%*"PRIu32":%02u",
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
	}

	attr_set(A_NORMAL, 0, NULL);
	for (; line <= win_lines; ++line) {
		move(line, 0);
		addch('~');
		clrtoeol();
	}
}

static void
draw_status_line(void)
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

	attr_set(live ? A_REVERSE : A_NORMAL, 0, NULL);
	printw("%4"PRId32, cur_number[live]);
	addch(seek_cmd);
	addch(atomic_load_lax(&paused) ? '.' : '>');

	attr_set(A_NORMAL, 0, NULL);
	printw(
			"%3"PRId64":%02u"
			" / "
			"%3"PRId64":%02u"
			" (%3u%%)",
			clock / 60, (unsigned)(clock % 60),
			duration / 60, (unsigned)(duration % 60),
			duration ? (unsigned)(clock * 100 / duration) : 0);

	{
		unsigned n = atomic_load_lax(&in0.ntracks);
		if (1 < n)
			printw(" [Track: %u/%u]", cur_track + 1, n);
	}

	printw(" [Vol: %3d%%]", atomic_load_lax(&volume));

	if (show_stream)
		printw(" [%s -> %s]",
				source_info.buf[
					birdlock_rd_acquire(&source_info.lock)
				],
				sink_info.buf[
					birdlock_rd_acquire(&sink_info.lock)
				]);

	info_rd = birdlock_rd_acquire(&info_msg_lock);
	if (*info_msg[info_rd]) {
		attr_set(A_BOLD, 1, NULL);
		addch(' ');
		addstr(info_msg[info_rd]);
		attr_set(A_NORMAL, 0, NULL);
		clrtoeol();
	} else {
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
handle_metadata_change(File *f)
{
	uint8_t filter_index = cur_filter[live];
	if (FILTER_CUSTOM_0 <= filter_index) {
		Expr *query = filter_exprs[filter_index];
		uint8_t filter_mask = UINT8_C(1) << filter_index;
		int match = expr_eval(query, &(ExprEvalContext const){
			.f = f,
			.match_data = re_match_data,
		});
		if (match != !!(filter_mask & f->filter_mask)) {
			f->filter_mask ^= filter_mask;
			nfiles[filter_index] += match ? 1 : -1;

			sort_pending[0] = 1;
			sort_pending[1] = 1;

			handle_filter_change();
		}
	}

	int old_live = live;
	for (live = 0; live < 2; ++live)
		if (!file_ordered(f)) {
			sort_has_order[live] = 0;
			sort_pending[live] = 1;
		}
	live = old_live;

	if (f == in0.seek_f)
		update_title();
}

static void
handle_signotify(int sig)
{
	(void)sig;
	enum Event got_events = atomic_exchange_lax(&pending_events, 0);

	if (EVENT_METADATA_CHANGED & got_events) {
		MetadataEvent *e = &in0.metadata_event[
			birdlock_rd_acquire(&in0.metadata_lock)
		];

		if (e->f == in0.seek_f) {
			int rc;
			if (AV_NOPTS_VALUE == e->duration)
				rc = read_stream_metadata(e);
			else
				rc = read_metadata(e);

			if (0 < rc) {
				got_events |= EVENT_FILE_CHANGED;
				handle_metadata_change(e->f);
			}
		}
	}

	if (EVENT_EOF_REACHED & got_events) {
		int old_live = live;
		switch_live(1);
		do_key(CONTROL('M'));
		switch_live(old_live);
	}

	if (((EVENT_FILE_CHANGED | EVENT_STATE_CHANGED) & got_events) &&
	    atomic_load_lax(&focused))
	{
		if (EVENT_FILE_CHANGED & got_events)
			draw_files();

		if ((EVENT_FILE_CHANGED | EVENT_STATE_CHANGED) & got_events)
			draw_status_line();

		draw_cursor();
		refresh();
	}
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");

	if (!(tty = fopen(ctermid(NULL), "w+e"))) {
		print_error("Cannot connect to TTY");
		exit(EXIT_FAILURE);
	}
	xassert(0 <= setvbuf(tty, NULL, _IONBF, 0));

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

		re_match_data = pcre2_match_data_create(0, NULL);

		if (!re_ucase || !re_match_data) {
			print_error("Failed to allocate PCRE2 structures");
			exit(EXIT_FAILURE);
		}
	}

#if WITH_ICU
	{
		UParseError parse_error;
		UErrorCode error_code = U_ZERO_ERROR;
		sort_ucol = ucol_openRules((UChar const[1]){ 0 }, 0,
				/* Normalize. */
				UCOL_ON,
				/* Compare base letters case-less. */
				UCOL_PRIMARY,
				&parse_error, &error_code);
		if (!sort_ucol) {
			print_error("Failed to open collator");
			exit(EXIT_FAILURE);
		}
		assert(U_SUCCESS(error_code));
	}
#endif

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
	for (int c; 0 <= (c = getopt(argc, argv, "q:e:a:c:f:o:m:C:s:dv"));)
		switch (c) {
		case 'q':
			if (!(search_history[0] = strdup(optarg))) {
				print_error("Failed to allocate memory");
				exit(EXIT_FAILURE);
			}
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

		case 'o':
			ofilename = optarg;
			break;

		case 'm':
			buffer_bytes_max = strtoll(optarg, NULL, 10) * 1024;
			break;

		case 'C':
			column_spec = optarg;
			break;

		case 's':
			if (!(sort_spec[live] = strdup(optarg))) {
				print_error("Failed to allocate memory");
				exit(EXIT_FAILURE);
			}
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
			notify_strerror("Cannot create worker thread");
			exit(EXIT_FAILURE);
		}

#if CONFIG_VALGRIND
		threads_inited = 1;
#endif
	}

	/* Open arguments. */
	{
		Playlist *master = append_playlist(NULL, "master");
		if (!master)
			exit(EXIT_FAILURE);
		master->read_only = 1;
		master->dirfd = open(".", O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);

		if (argc <= optind) {
			if (!isatty(STDIN_FILENO)) {
				File *f = append_file_dupurl(master, F_PLAYLIST, "stdin");
				if (!f)
					exit(EXIT_FAILURE);
				Playlist *playlist = append_playlist(f, f->url);
				if (!playlist)
					exit(EXIT_FAILURE);
				playlist->read_only = 1;
				playlist->dirfd = dup(master->dirfd);
				read_playlist_m3u(playlist, dup(STDIN_FILENO));
			} else {
				File *f = append_file_dupurl(master, F_PLAYLIST_DIRECTORY, ".");
				if (!f)
					exit(EXIT_FAILURE);
				read_file(f);
			}
		} else for (; optind < argc; ++optind) {
			char const *url = argv[optind];
			enum FileType type = probe_url(master, url);
			File *f = append_file_dupurl(master, type, url);
			if (!f)
				exit(EXIT_FAILURE);
			read_file(f);
		}
	}

	if (search_history[0]) {
		ExprParserContext parser;
		filter_files(&parser, search_history[0]);
		if (parser.error_msg) {
			print_error("Failed to parse search query");
			exit(EXIT_FAILURE);
		}
	}

	if (!startup_cmd)
		startup_cmd = "s";
	do_keys(startup_cmd);

	/* Disconnect stderr unless redirected. */
	{
		struct stat st_stdin, st_stderr;
		if (fstat(STDIN_FILENO, &st_stdin) < 0 ||
		    fstat(STDERR_FILENO, &st_stderr) < 0 ||
		    (st_stdin.st_dev == st_stderr.st_dev &&
		     st_stdin.st_ino == st_stderr.st_ino))
			freopen("/dev/null", "w+", stderr);
	}

	/* TUI event loop. */
	{
		pthread_setname_np(pthread_self(), "muck/tty");
		newterm(NULL, stdout, tty);
		start_color();
		use_default_colors();
		init_pair(1, 1, -1);
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
