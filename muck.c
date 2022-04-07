#include <locale.h>
#include <unistd.h>

#include "files.h"
#include "player.h"
#include "tui.h"
#include "expr.h"
#include "file.h"
#include "playlist.h"
#include "env.h"

#include "config.h"
#include "playlist.h"

#include <libavcodec/avcodec.h>
#include <libavdevice/avdevice.h>
#include <libavfilter/avfilter.h>
#include <libavformat/avformat.h>

#define FEATURES \
	/* xmacro(flag, name) */ \
	xmacro(WITH_ICU, "icu")

#define FEATURE_HAVE0 "-"
#define FEATURE_HAVE1 "+"
#define FEATURE_HAVE(flag) FEATURE_HAVE##flag

#define FLAG0 "+"
#define FLAG1 "+"
#define FEATURE_STR(ICU)

static void
bye(void)
{
	tui_destroy();

	Error error;
	error_reset(&error);
	playlists_save(&error);

#if CONFIG_VALGRIND
	player_destroy();
	files_destroy();
	expr_global_uninit();
#endif
}

static void
open_cmdline(int argc, char *argv[], FileReadError *error)
{
	Playlist *master = playlist_alloc_master();
	if (!master)
		goto fail_enomem;

	if (!argc) {
		if (!isatty(STDIN_FILENO)) {
			File *f = playlist_alloc_file_dupurl(master, F_PLAYLIST, "stdin");
			if (!f)
				goto fail_enomem;
			Playlist *playlist = playlist_alloc(f, f->url);
			if (!playlist)
				goto fail_enomem;
			playlist->read_only = 1;
			playlist->dirname = strdup(".");
			if (!playlist->dirname)
				goto fail_enomem;
			playlist->dirfd = dup(master->dirfd);
			playlist_read_m3u(playlist, dup(STDIN_FILENO), error);
		} else {
			File *f = playlist_alloc_file_dupurl(master, F_PLAYLIST_DIRECTORY, ".");
			if (!f)
				goto fail_enomem;
			file_read(f, error);
		}
	} else for (int i = 0; i < argc; ++i) {
		char const *url = argv[i];
		enum FileType type = playlist_probe_url(master, url);
		File *f = playlist_alloc_file_dupurl(master, type, url);
		if (!f)
			goto fail_enomem;
		file_read(f, error);
	}

	return;

fail_enomem:
	error_from_strerror(&error->error, ENOMEM);
}

int
main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");
	atexit(bye);

	Error error;
	error_reset(&error);

	env_init(&error);
	expr_global_init(&error);
	files_init(&error);
	tui_init();
	player_init(&error);

	error_ok_or_die(&error, "Could not initalize globals");

	char const *startup_cmd = "0G";
	char const *codec = "pcm";
	char const *format_name = "alsa";
	char const *filename = NULL;
	char const *graph_descr = "volume=replaygain=track";

	for (int c; 0 <= (c = getopt(argc, argv, "q:e:a:c:f:o:m:C:s:dv"));)
		switch (c) {
		case 'q':
		{
			ExprParserContext parser;
			error_reset(&parser.error);

			char *s = strdup(optarg);
			if (!s)
				error_from_errno(&parser.error);
			else
				files_set_filter(&parser, s);
			error_ok_or_die(&parser.error, "invalid argument for 'q'");
		}
			break;

		case 'e':
			startup_cmd = optarg;
			break;

		case 'a':
			graph_descr = optarg;
			break;

		case 'c':
			codec = optarg;
			break;

		case 'f':
			format_name = optarg;
			break;

		case 'o':
			filename = optarg;
			break;

		case 'm':
			player_set_buffer(strtoll(optarg, NULL, 10) * 1024);
			break;

		case 'C':
			tui_set_columns(optarg);
			break;

		case 's':
		{
			char *s = strdup(optarg);
			if (!s)
				error_from_errno(&error);
			error_ok_or_die(&error, "invalid argument for 's'");
			files_set_order(s);
		}
			break;

		case 'd':
			av_log_set_level(av_log_get_level() < AV_LOG_DEBUG ? AV_LOG_DEBUG : AV_LOG_TRACE);
			break;

		case 'v':
#define xmacro(flag, name) " " FEATURE_HAVE(flag) name
			puts(MUCK_VERSION);
			puts("Features:" FEATURES);
#undef xmacro
			printf("FFmpeg %s:\n"
					"  %s: %s\n"
					"  %s: %s\n"
					"  %s: %s\n"
					"  %s: %s\n"
					"  %s: %s\n",
					av_version_info(),
					LIBAVUTIL_IDENT, avutil_configuration(),
					LIBAVCODEC_IDENT, avcodec_configuration(),
					LIBAVFORMAT_IDENT, avformat_configuration(),
					LIBAVFILTER_IDENT, avfilter_configuration(),
					LIBAVDEVICE_IDENT, avdevice_configuration());
			return EXIT_SUCCESS;

		default:
			return EXIT_FAILURE;
		}

	player_configure(format_name, filename, codec, graph_descr);

	player_run(&error);
	error_ok_or_die(&error, "Could not start player");

	FileReadError read_error;
	error_reset(&read_error.error);
	open_cmdline(argc - optind, argv + optind, &read_error);
	error_ok_or_die(&read_error.error, "Could not populate files from command line");

	tui_feed_keys(startup_cmd);
	tui_run();
}
