#include "assert_utils.h"
#include "atomic_utils.h"
#include "compat/pthread.h"
#include "math_utils.h"
#include "stdio_utils.h"
#include <ncurses.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "birdlock.h"
#include "env.h"
#include "expr.h"
#include "fdata.h"
#include "files.h"
#include "playlist.h"
#include "tmpf.h"
#include "tui.h"

#define CONTROL(c) ((c) - '@')

enum {
	KEY_FOCUS_IN = 1001,
	KEY_FOCUS_OUT = 1002,
};
static char const SEND_FOCUS_EVENTS[] = "\033[?1004h";
static char const STOP_FOCUS_EVENTS[] = "\033[?1004l";

static atomic_uchar ALIGNED_ATOMIC pending_events;
static atomic_uchar ALIGNED_ATOMIC focused = 1;

static int64_t notified_clock, notified_duration;

static FILE *tty;
static int32_t top;
static int32_t left;
static int sel_y, sel_x;

static int widen;
static atomic_uchar show_stream;

static char user_msg[2][128];
static uint8_t user_msg_rd;
static BirdLock user_msg_lock;

static char const *column_spec = "iy30a,x25A+Fd*20Tn*40t+f+vlgbIB*LCoOm*z";

static pthread_t tui_thread;

static char number_cmd[2];
static int32_t cur_number[2];

static char seek_cmd = 'n';
static unsigned cur_track = 0;

static int
tui_is_focused(void)
{
	return atomic_load_lax(&focused);
}

static void
tui_stop(void)
{
	if (!tty)
		return;

	fputs(STOP_FOCUS_EVENTS, tty);
	endwin();
}

void
tui_destroy(void)
{
	tui_stop();
}

static void
tui_dismiss_msg(void)
{
	if (!*user_msg[user_msg_rd])
		return;
	*user_msg[user_msg_rd] = '\0';
	tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
}

int
tui_shellout(void)
{
	tui_dismiss_msg();
	tui_stop();

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

static void
tui_shellout_script(int c)
{
	File const *f = files_seek(0, SEEK_CUR);
	if (!f)
		return;

	struct timespec mtim_before = file_get_mtim(f);

	if (!tui_shellout()) {
		Playlist *playlist = file_get_playlist(f);
		if (fchdir(playlist->dirfd) < 0)
			_exit(EXIT_FAILURE);

		if (f) {
			if (F_FILE == f->type)
				setenv("MUCK_PATH", f->url, 0);

			char name[5 + METADATA_NAME_MAXSZ + 1 /* NUL */] = "MUCK_";

			for (enum MetadataX m = 0; m < MX_NB; ++m) {
				memcpy(name + 5, metadata_get_name(m), METADATA_NAME_MAXSZ);
				char buf[FILE_METADATAX_BUFSZ];
				char const *value = file_get_metadata(f, m, buf);
				if (value)
					setenv(name, value, 0);
			}
		}

		char exe[PATH_MAX];
		if (0 <= safe_sprintf(exe, "%s/%c", config_home, c))
			execl(exe, exe, f->url, NULL);

		_exit(EXIT_FAILURE);
	}

	struct timespec mtim_after = file_get_mtim(f);

	if (memcmp(&mtim_before, &mtim_after, sizeof mtim_before))
		player_seek_file(f, player_get_clock(), cur_track);
}

static void
handle_sigwinch(int sig)
{
	(void)sig;

	struct winsize w;
	if (!ioctl(fileno(tty), TIOCGWINSZ, &w)) {
		resize_term(w.ws_row, w.ws_col);
		tui_feed_key(CONTROL('L'));
	}
}

static void
handle_sigcont(int sig)
{
	(void)sig;
	tui_feed_key(CONTROL('L'));
}

static void
handle_sigexit(int sig)
{
	(void)sig;
	exit(EXIT_SUCCESS);
}

static int
read_metadata(PlayerMetadataEvent const *e)
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

	FileData fdata;
	fdata_reset_with_url(&fdata, f->url);

	if (AV_NOPTS_VALUE != e->duration) {
		int rc = fdata_writef(&fdata, M_length,
				"%"PRId64,
				av_rescale(e->duration, 1, AV_TIME_BASE));
		if (rc < 0)
			goto fail_too_long;
	}

	if (e->mtime &&
	    fdata_write_date(&fdata, M_mtime, e->mtime) < 0)
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
				if (fdata_append(&fdata, e->m, t->value) < 0)
					goto fail_too_long;

			if (fdata.f.metadata[e->m])
				break;
		}

	if (fdata_write_basic(&fdata, e) < 0)
		goto fail_too_long;

	int rc = fdata_save(&fdata, f);
	if (rc < 0)
		tui_msg_strerror_oom();
	return rc;

fail_too_long:
	tui_msgf("Too much metadata");
	return -1;
}

static int
read_stream_metadata(PlayerMetadataEvent const *e)
{
	AVDictionary const *m = e->metadata;
	File *f = e->f;

	FileData fdata;
	fdata_reset_with_url(&fdata, f->url);

	AVDictionaryEntry const *t;
	AVDictionaryEntry const *t2;

	/* Should not fail since it has been already stored. */
	xassert(0 <= fdata_write_basic(&fdata, e));

	t = av_dict_get(m, "icy-name", NULL, 0);
	if (!t || !*t->value)
		t = av_dict_get(m, "icy-url", NULL, 0);

	t2 = av_dict_get(m, "icy-description", NULL, 0);

	(void)fdata_writef(&fdata,
			M_artist, "%s%s%s",
			t && *t->value ? t->value : f->url,
			t2 && *t2->value ? " - " : "",
			t2 && *t2->value ? t2->value : "");

	t = av_dict_get(m, "StreamTitle", NULL, 0);
	if (t)
		(void)fdata_writef(&fdata,
				M_title, "%s", *t->value ? t->value : "ID");

	t = av_dict_get(m, "icy-genre", NULL, 0);
	if (t && *t->value)
		(void)fdata_writef(&fdata,
				M_genre, "%s", t->value);

	int rc = fdata_save(&fdata, f);
	if (rc < 0)
		tui_msg_strerror_oom();
	return rc;
}

static void
tui_draw_files(void)
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

		enum MetadataX m;
		if (!metadata_parse(&m, *end))
			break;

		if (s == end) {
			if ((MX_index == m ||
			     MX_visual_index == m) &&
			    nfiles[FILTER_ALL])
				n = ceil(log(nfiles[FILTER_ALL]) / log(10));
			else
				n = metadata_get_def_width(m);
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

	File const *playing = player_get_file();
	File const *sel = files_seek(0, SEEK_CUR);
	int32_t sel_index = sel ? sel->index[live] : 0;
	int32_t old_top = top;
	int32_t scrolloff = 5;
	int32_t n = nfiles[cur_filter[live]];

	top = MIN(top, sel_index - scrolloff);
	top = MAX(top + win_lines, sel_index + 1 + scrolloff) - win_lines;
	top = MIN(top + win_lines, n) - win_lines;
	top = MAX(top, 0);

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

		char const *name = metadata_get_name((enum MetadataX)c->m);
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
		if (cur == sel)
			sel_y = line;

		move(line, 0);

		attr_t attrs = A_NORMAL;
		attrs |= cur == sel && !live ? A_REVERSE : 0;
		attrs |= cur == playing ? A_BOLD : 0;
		attr_set(attrs, 0, NULL);

		if (!cur->metadata[M_title]) {
			char const *url = cur->url;
			if (F_URL != cur->type)
				url = file_get_metadata(cur, MX_name, NULL);
			addstr(url);
			for (int curx = getcurx(stdscr); curx < COLS; ++curx)
				addch(' ');
		} else {
			int x = 0;
			for (c = defs; c < endc; ++c) {
				char buf[FILE_METADATAX_BUFSZ];
				char const *s = file_get_metadata(cur, c->mx, buf);
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
tui_draw_cursor(void)
{
	move(sel_y, sel_x);
}

static void
tui_draw_status_line(void)
{
	int64_t clock = player_get_clock();
	int64_t duration = player_get_duration();

	int y = LINES - 1;

	move(y, 0);

	attr_set(live ? A_REVERSE : A_NORMAL, 0, NULL);
	printw("%4"PRId32, cur_number[live]);
	addch(seek_cmd);
	addch(player_is_paused() ? '.' : '>');

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
		unsigned n = player_get_ntracks();
		if (1 < n)
			printw(" [Track: %u/%u]", cur_track + 1, n);
	}

	printw(" [Vol: %3d%%]", player_get_volume());

	if (show_stream)
		printw(" [%s -> %s]",
				player_get_source_info(),
				player_get_sink_info());

	user_msg_rd = birdlock_rd_acquire(&user_msg_lock);
	if (*user_msg[user_msg_rd]) {
		attr_set(A_BOLD, 1, NULL);
		addch(' ');
		addstr(user_msg[user_msg_rd]);
		attr_set(A_NORMAL, 0, NULL);
		clrtoeol();
#if 0
	} else if (1) {
		printw(" %s", player_get_debug_info());
		clrtoeol();
#endif
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
tui_draw_title(void)
{
	File const *f = player_get_file();

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
tui_set_live(int new_live)
{
	/* Preserve selection on entering visual mode. */
	File const *cur = player_get_file();
	if (!new_live && cur)
		files_select(cur);

	files_set_live(new_live);

	cur_number[0] = cur_number[1];
	number_cmd[0] = '\0';
	number_cmd[1] = '\0';
}

void
tui_handle_files_change(void)
{
	if (!live)
		return;

	/* Ensure currently playing file is not filtered. */
	File *f = files_seek(0, SEEK_CUR);
	if (f != player_get_file())
		tui_notify(TUI_EVENT_EOF_REACHED);
}

static void
handle_signotify(int sig)
{
	(void)sig;
	enum TUIEvent got_events = atomic_exchange_lax(&pending_events, 0);

	if (TUI_EVENT_METADATA_CHANGED & got_events) {
		PlayerMetadataEvent *e = player_get_metadata();
		if (e) {
			int rc;
			if (AV_NOPTS_VALUE == e->duration)
				rc = read_stream_metadata(e);
			else
				rc = read_metadata(e);
			if (0 < rc) {
				got_events |= TUI_EVENT_FILES_CHANGED;
				files_dirty_single(e->f);
				if (e->f == player_get_file())
					tui_draw_title();

				/* Avoid race-condition by sending eof signal
				 * twice. */
				if (!(TUI_EVENT_EOF_REACHED & got_events))
					tui_handle_files_change();
			}
		}
	}

	if (TUI_EVENT_EOF_REACHED & got_events) {
		int old_live = live;
		files_set_live(1);
		tui_feed_key(CONTROL('M'));
		files_set_live(old_live);
	}

	if (((TUI_EVENT_FILES_CHANGED | TUI_EVENT_STATUS_LINE_CHANGED) & got_events) &&
	    tui_is_focused())
	{
		if (TUI_EVENT_FILES_CHANGED & got_events) {
			tui_draw_files();
			/* files_do_filtersort() may generate a change
			 * notification before doing the actual rendering. Such
			 * events can be generated by this thread only, so it
			 * is safe to clear the flag, in order to save a
			 * needless redraw. */
			atomic_fetch_and_lax(&pending_events, ~TUI_EVENT_FILES_CHANGED);
		}

		if (TUI_EVENT_STATUS_LINE_CHANGED & got_events)
			tui_draw_status_line();

		tui_draw_cursor();
		refresh();
	}
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

void
tui_select(File *f)
{
	if (!f)
		return;

	if (live) {
		cur_track = 0;
		player_seek_file(f, AV_NOPTS_VALUE, cur_track);
	} else {
		files_select(f);
	}
	tui_notify(TUI_EVENT_FILES_CHANGED | TUI_EVENT_STATUS_LINE_CHANGED);
}

void
tui_notify(enum TUIEvent event)
{
	if (!atomic_fetch_or_lax(&pending_events, event))
		xassert(!pthread_kill(tui_thread, SIGRTMIN));
}

void
tui_player_notify(enum PlayerEvent event)
{
	static enum TUIEvent const MAP[] = {
		[PLAYER_EVENT_PLAYBACK_CHANGED] = TUI_EVENT_STATUS_LINE_CHANGED,
		[PLAYER_EVENT_STREAM_CHANGED] = TUI_EVENT_STATUS_LINE_CHANGED,
		[PLAYER_EVENT_METADATA_CHANGED] = TUI_EVENT_METADATA_CHANGED,
		[PLAYER_EVENT_EOF_REACHED] = TUI_EVENT_EOF_REACHED,
	};

	if (PLAYER_EVENT_STREAM_CHANGED == event &&
	    !atomic_load_lax(&show_stream))
		return;

	tui_notify(MAP[event]);
}

void
tui_player_notify_progress(void)
{
	if (!tui_is_focused())
		return;

	int64_t clock = player_get_clock();
	int64_t duration = player_get_duration();

	if (clock == notified_clock && duration == notified_duration)
		return;

	notified_clock = clock;
	notified_duration = duration;

	tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
}

void
tui_msgf(char const *format, ...)
{
	char *buf = user_msg[
		birdlock_wr_acquire(&user_msg_lock)
	];

	va_list ap;
	va_start(ap, format);
	vsnprintf(buf, sizeof user_msg[0], format, ap);
	va_end(ap);

	birdlock_wr_release(&user_msg_lock);

	tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
}

void
tui_msg_error(Error *error)
{
	tui_msgf("%s", error->msg);
}

void
tui_msg_strerror(char const *msg)
{
	tui_msgf("%s: %s", msg, strerror(errno));
}

void
tui_msg_strerror_oom(void)
{
	tui_msg_strerror("Cannot allocate memory");
}

void
tui_msg_oom(void)
{
	errno = ENOMEM;
	tui_msg_strerror_oom();
}

static void
print_syntax_help(File const *f, FILE *stream)
{
	fputs("# Keys:\n", stream);
	for (enum MetadataX i = 0; i < MX_NB; ++i) {
		char buf[FILE_METADATAX_BUFSZ];
		char const *value = f ? file_get_metadata(f, i, buf) : NULL;
		fprintf(stream, "# %c%c=%-*s%s\n",
				METADATASET_IN_URL & metadata_to_set(i) ? '+' : ' ',
				metadata_get_id(i),
				value ? METADATA_NAME_MAXSZ + 1 /* Separator SP. */ : 0,
				metadata_get_name(i),
				value ? value : "");
	}
}

static void
cat_history_file(char const *name, FILE *stream)
{
	char history_path[PATH_MAX];
	int rc = safe_sprintf(history_path, "%s/%s", config_home, name);

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
		size_t sz;
		while (0 < (sz = fread(buf, 1, sizeof buf, history)))
			fwrite(buf, 1, sz, stream);
		fclose(history);
	} else {
		fprintf(stream, "# %s.\n", strerror(errno));
	}
	fputc('\n', stream);
}

static void
tui_set_order_visual(void)
{
	TemporaryFile tmpf;
	Error error;
	error_reset(&error);
	FILE *stream = tmpf_open(&tmpf, &error);
	if (!stream) {
		tui_msg_error(&error);
		return;
	}

	fputs(files_get_order(), stream);
	fputc('\n', stream);

	fputc('\n', stream);

	cat_history_file("sort-history", stream);

	File *cur = files_seek(0, SEEK_CUR);
	print_syntax_help(cur, stream);

	fclose(stream);

	char *line = tmpf_readline(&tmpf);
	if (!line)
		return;

	files_set_order(line);
}

static void
tui_set_filter_visual(void)
{
	ExprParserContext parser;
	error_reset(&parser.error);

reopen:
	Error error;
	error_reset(&error);
	TemporaryFile tmpf;
	FILE *stream = tmpf_open(&tmpf, &error);
	if (!stream) {
		tui_msg_error(&error);
		return;
	}

	if (!error_is_ok(&parser.error))
		fprintf(stream, "%.*s<ERROR>%s\n"
				"# Error: %s\n\n",
				(int)(parser.ptr - parser.src), parser.src,
				parser.ptr,
				parser.error.msg);

	int any = 0;
	for (size_t i = 0; i < FF_ARRAY_ELEMS(search_history) && search_history[i]; ++i)
	{
		fprintf(stream, "%s\n", search_history[i]);
		any = 1;
	}
	if (!any)
		fputc('\n', stream);
	fputc('\n', stream);

	File *cur = files_seek(0, SEEK_CUR);
	if (cur) {
		for (enum MetadataX i = 0; i < MX_NB; ++i) {
			char buf[FILE_METADATAX_BUFSZ];
			char const *value = file_get_metadata(cur, i, buf);
			if (!value || !*value)
				continue;

			fputc(metadata_get_id(i), stream);
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

	char *line = tmpf_readline(&tmpf);
	if (!line)
		return;

	files_set_filter(&parser, line);
	if (!error_is_ok(&parser.error))
		goto reopen;
}

void
tui_feed_key(int c)
{
	if ('0' <= c && c <= '9') {
		cur_number[live] = 10 * get_number(0) + (c - '0');
		number_cmd[live] = '0';
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
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
		player_set_volume(MAXMIN(-100, get_number(-player_get_volume()), 100));
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case '+':
		player_set_volume(MIN(abs(player_get_volume()) + 1, 100));
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case '-':
		player_set_volume(MAX(0, abs(player_get_volume()) - 2));
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case 'v':
		tui_set_live(live ^ 1);
		tui_notify(TUI_EVENT_FILES_CHANGED | TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case 't': /* Tracks. */
	{
		unsigned n = player_get_ntracks();
		if (n) {
			cur_track += 1;
			cur_track %= n;
			File *cur = player_get_file();
			if (cur)
				player_seek_file(cur, player_get_clock(), cur_track);
		}
	}
		break;

	case '/': /* Search. */
		tui_set_filter_visual();
		break;

	case '|':
		if (isatty(fileno(stdout))) {
			Error error;
			error_reset(&error);
			TemporaryFile tmpf;
			FILE *stream = tmpf_open(&tmpf, &error);
			if (!stream)
				break;

			files_plumb(stream);
			fclose(stream);

			free(tmpf_readline(&tmpf));
		} else {
			files_plumb(stdout);
		}
		break;

	case 'e': /* Edit. */
	{
		if (live) {
			player_seek(1, SEEK_CUR);
			break;
		}

	}
		break;

	case 'r': /* Random. */
		if (live) {
			char old_seek_cmd = seek_cmd;
			seek_cmd = 'r';
			tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
			if ('g' == old_seek_cmd)
				break;
		}

		tui_select(files_seek_rnd(SEEK_CUR));
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
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);

		if ('g' == old_seek_cmd)
			break;

		tui_select(files_seek(cur_number[live] * dir, SEEK_CUR));
	}
		break;

	case 'g': /* Go to. */
	case KEY_HOME:
	{
		if (live)
			seek_cmd = 'g';
		use_number('g', 0);
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);

		if (live) {
			uint64_t ts =
				cur_number[live] / 100 * 60 /* min */ +
				cur_number[live] % 100 /* sec */;
			player_seek(ts, SEEK_SET);
		} else {
			tui_select(files_seek(0, SEEK_SET));
		}
	}
		break;

	case 'G': /* GO TO. */
	case KEY_END:
		if (live) {
			int32_t n = get_number(100 * 3 / 8);
			player_seek(player_get_duration() * n / 100, SEEK_SET);
		} else {
			tui_select(files_seek(0, SEEK_END));
		}
		break;

	case 'H':
	case KEY_SLEFT:
	case 'L':
	case KEY_SRIGHT:
		left += 'H' == c || KEY_SLEFT == c ? -1 : 1;
		tui_notify(TUI_EVENT_FILES_CHANGED);
		break;

	case 'h':
	case KEY_LEFT:
	case 'l':
	case KEY_RIGHT:
	{
		int dir = 'h' == c || KEY_LEFT == c ? -1 : 1;
		int32_t n = get_number(5);
		player_seek(n * dir, SEEK_CUR);
	}
		break;

	case 'j':
	case 'k':
	{
		int dir = 'j' == c ? -1 : 1;
		if (live) {
			int32_t n = get_number(MAX(player_get_duration() / 16, +5));
			player_seek(n * dir, SEEK_CUR);
		} else {
			tui_select(files_seek(get_number(1) * -dir, SEEK_CUR));
		}
	}
		break;

	case '.':
	case '>':
		player_pause('.' == c);
		break;

	case 'c': /* Continue. */
	case ' ':
		player_pause(!player_is_paused());
		break;

	case 'a': /* After. */
	case 'b': /* Before. */
		if (live && 'b' == c) {
			player_seek(-2, SEEK_CUR);
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
		tui_set_order_visual();
		break;

	case 'w':
		widen ^= 1;
		tui_notify(TUI_EVENT_FILES_CHANGED);
		break;

	case 's': /* Set. */
	{
		int64_t n = get_number(0);

		if (live) {
			/* Stay close to file, even if it fails to play. */
			if ('p' != seek_cmd && 'n' != seek_cmd) {
				seek_cmd = 'n';
				number_cmd[live] = '\0';
				tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
			}
		}

		tui_select(files_seek(n, SEEK_SET));
	}
		break;

	case 'i':
		atomic_fetch_xor_lax(&show_stream, 1);
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case '?':
	case KEY_F(1):
		if (!tui_shellout()) {
			execlp("man", "man", "muck.1", NULL);
			_exit(EXIT_FAILURE);
		}
		break;

	case CONTROL('L'):
		tui_dismiss_msg();
		clear();
		tui_notify(TUI_EVENT_FILES_CHANGED | TUI_EVENT_STATUS_LINE_CHANGED);
		break;

	case CONTROL('M'):
	{
		File *f = files_seek(0, SEEK_CUR);
		if (!f)
			break;

		int old_live = live;
		files_set_live(1);
		tui_select(f);
		files_set_live(old_live);

		player_pause(0);
	}
		break;

	case 'Z': /* Zzz. */
	case 'q':
		exit(EXIT_SUCCESS);

	default:
		if (' ' <= c && c <= '~')
			tui_shellout_script(c);
		break;

	case KEY_FOCUS_IN:
	case KEY_FOCUS_OUT:
		atomic_store_lax(&focused, KEY_FOCUS_IN == c);
		tui_notify(TUI_EVENT_FILES_CHANGED | TUI_EVENT_STATUS_LINE_CHANGED);
		break;
	}

	if ('0' == number_cmd[live]) {
		number_cmd[live] = '\0';
		cur_number[live] = 0;
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
	}
}

void
tui_feed_keys(char const *s)
{
	while (*s)
		tui_feed_key(*s++);
}

static void
setup_signals(void)
{
	sigset_t watched;
	xassert(!sigemptyset(&watched));
	xassert(!sigaddset(&watched, SIGCONT));
	xassert(!sigaddset(&watched, SIGWINCH));
	xassert(!sigaddset(&watched, SIGINT));
	xassert(!sigaddset(&watched, SIGHUP));
	xassert(!sigaddset(&watched, SIGTERM));
	xassert(!sigaddset(&watched, SIGQUIT));
	xassert(!sigaddset(&watched, SIGPIPE));
	xassert(!sigaddset(&watched, SIGRTMIN));
	xassert(!pthread_sigmask(SIG_BLOCK, &watched, NULL));

	struct sigaction sa;
	sa.sa_flags = SA_RESTART;
	xassert(!sigfillset(&sa.sa_mask));

	sa.sa_handler = handle_sigcont;
	xassert(!sigaction(SIGCONT, &sa, NULL));

	sa.sa_handler = handle_sigexit;
	xassert(!sigaction(SIGINT, &sa, NULL));
	xassert(!sigaction(SIGHUP, &sa, NULL));
	xassert(!sigaction(SIGTERM, &sa, NULL));
	xassert(!sigaction(SIGQUIT, &sa, NULL));

	sa.sa_handler = SIG_IGN;
	xassert(!sigaction(SIGPIPE, &sa, NULL));

	sa.sa_handler = handle_sigwinch;
	xassert(!sigaction(SIGWINCH, &sa, NULL));

	sa.sa_handler = handle_signotify;
	xassert(!sigaction(SIGRTMIN, &sa, NULL));
}

void
tui_init(void)
{
	setup_signals();
	tui_thread = pthread_self();

	if ((tty = fopen(ctermid(NULL), "w+e"))) {
		xassert(0 <= setvbuf(tty, NULL, _IONBF, 0));
		return;
	}

	tty = stdin;
}


static void
tui_redirect_stderr(void)
{
	if (isatty(STDERR_FILENO))
		freopen("/dev/null", "w+", stderr);
}

void
tui_run(void)
{
	tui_redirect_stderr();

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

	sigset_t enable_all;
	xassert(!sigemptyset(&enable_all));

	for (;;) {
		int rc = ppoll(&pollfd, 1, NULL, &enable_all);
		if (rc <= 0 && EINTR == errno)
			continue;
		if (rc <= 0 || (~POLLIN & pollfd.revents))
			exit(EXIT_SUCCESS);

		for (int key; ERR != (key = getch());)
			tui_feed_key(key);
	}
}

void
tui_set_columns(char const *spec)
{
	column_spec = spec;
}
