#include "assert_utils.h"
#include "stdio_utils.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "error.h"
#include "fdata.h"
#include "files.h"
#include "math_utils.h"
#include "playlist.h"

int16_t nplaylists;
Playlist **playlists;

#define COMPRESSORS \
	/* xmacro(ext, program) */ \
	xmacro(".bz", "bzip2") \
	xmacro(".bz2", "bzip2") \
	xmacro(".gz", "gzip") \
	xmacro(".lz4", "lz4") \
	xmacro(".xz", "xz") \
	xmacro(".zst", "zstd")

#define IS_SUFFIX(haystack, needle) ( \
	strlen(needle) <= haystack##_size && \
	!memcmp(haystack + haystack##_size - strlen(needle), needle, strlen(needle)) && \
	(haystack##_size -= strlen(needle), 1) \
)

static inline int
opendirat(int fd, char const *path)
{
	return openat(fd, path, O_CLOEXEC | O_PATH | O_RDONLY | O_DIRECTORY);
}

static int
file_playlist_order_cmp(void const *px, void const *py)
{
	File const *x = *(File **)px;
	File const *y = *(File **)py;

	return DIFFSIGN(x->playlist_order, y->playlist_order);
}

static void
file_write_m3u(File const *f, FILE *stream)
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

		fprintf(stream, " %s=\"", metadata_get_name((enum MetadataX)i));
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


static int
reap(pid_t pid)
{
	int status;
	xassert(0 <= waitpid(pid, &status, 0));

	if (!(WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status)))
		return -1;
	return 0;
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
playlist_pipe_compress(Playlist *playlist, int *playlist_fd, pid_t *pid, int do_compress)
{
	int pipes[2] = { -1, -1 };

	(void)pipe2(pipes, O_CLOEXEC);

	if ((*pid = fork()) < 0) {
		/* tui_msgf("Cannot %s playlist: %s",
				do_compress ? "compress" : "decompress",
				playlist->name); */
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

static int
arrayrealloc_pow2(void *pp, int32_t nmemb, int32_t size)
{
	if (!((nmemb + 1) & nmemb)) {
		/* XXX: May overflow. */
		void *p = realloc(*(void **)pp, ((nmemb + 1) * 2 - 1) * size);
		if (!p)
			return -ENOMEM;
		*(void **)pp = p;
	}

	return 0;
}

void
file_read(File *f, FileReadError *error)
{
	if (f->type <= F_FILE)
		return;

	error->lnum = 0;
	error->col = 0;
	error->playlist = NULL;

	Playlist *parent = file_get_playlist(f);
	int fd = openat(parent->dirfd, f->url, O_CLOEXEC | O_RDONLY);
	if (fd < 0) {
		error_setf_strerror(&error->error, "Cannot open '%s'", f->url);
		return;
	}

	Playlist *playlist = playlist_alloc(f, f->url);
	if (!playlist) {
		error_from_errno(&error->error);
		close(fd);
		return;
	}

	error->playlist = playlist;
	playlist_read(playlist, fd, error);
}

void
playlist_read_dir(Playlist *playlist, FileReadError *error)
{
	DIR *dir = fdopendir(dup(playlist->dirfd));
	if (!dir) {
		error_from_errno(&error->error);
		return;
	}

	for (struct dirent *dent; (dent = readdir(dir));) {
		char const *name = dent->d_name;
		if ('.' == *name)
			continue;

		enum FileType type = playlist_probe_url(NULL, name);
		File *f = playlist_alloc_file_dupurl(playlist, type, name);
		file_read(f, error);
	}

	closedir(dir);
}

void
playlist_read_m3u(Playlist *playlist, int fd, FileReadError *error)
{
	FileData fdata;

	char buf[PLAYLIST_LINE_MAXSZ];
	size_t bufsz = 0;
	char *line = buf;

	int is_m3u = 0;

	size_t lnum = 1;
	char *col;

	fdata_reset(&fdata, 1);

	for (;;) {
		col = NULL;

		char *line_end;
		while (!(line_end = memchr(line, '\n', bufsz))) {
			if (sizeof buf - 1 == bufsz) {
				error->error.msg = "Too long line";
				goto fail;
			}

			memmove(buf, line, bufsz);
			line = buf;

			ssize_t len = read(fd, buf + bufsz, (sizeof buf - 1) - bufsz);
			if (len < 0) {
				error->error.msg = "Cannot read playlist stream";
				goto fail;
			} else if (!len) {
				if (!bufsz)
					goto out;

				line_end = buf + bufsz;
				++bufsz;
				break;
			}

			bufsz += len;
		}

		*line_end = '\0';

		if (1 == lnum && !strcmp(line, "#EXTM3U")) {
			is_m3u = 1;
		} else if (is_m3u && '#' == *line) {
#define IS_DIRECTIVE(directive) \
	(!memcmp(line + 1, directive, strlen(directive)) && \
	 (col = line + 1 + strlen(directive)))

			if (IS_DIRECTIVE("EXTINF:")) {
				fdata_reset(&fdata, 1);

				fdata.f.metadata[M_length] = fdata.sz;
				while ('0' <= *col && *col <= '9') {
					if (sizeof fdata.buf - 1 < fdata.sz) {
					fail_too_long:
						error->error.msg = "Too much data";
						goto fail;
					}
					fdata.buf[fdata.sz++] = *col++;
				}
				fdata.buf[fdata.sz++] = '\0';

				for (;;) {
					while (' ' == *col)
						++col;

					if (',' == *col) {
						++col;
						break;
					} else if (!*col) {
						error->error.msg = "Expected , or parameter name";
						goto fail;
					}

					char *equal = strchr(col, '=');
					if (!equal) {
						error->error.msg = "Expected = after parameter name";
						goto fail;
					}
					*equal = '\0';

					enum Metadata m;
					for (m = 0; m < M_NB; ++m)
						if (!strcmp(col, metadata_get_name((enum MetadataX)m)))
							break;

					switch (m) {
					case M_NB:
					/* Supplied in another way. */
					case M_length:
						error->error.msg = "Unknown parameter";
						goto fail;

					default:;
					}
					col = equal + 1;

					if ('"' != *col) {
						error->error.msg = "Expected \" after =";
						goto fail;
					}
					++col;

					fdata.f.metadata[m] = fdata.sz;
					for (;;) {
						if ('"' == *col) {
							++col;
							break;
						}

						col += '\\' == *col;
						if (!*col) {
							error->error.msg = "Unterminated \"";
							goto fail;
						}

						if (sizeof fdata.buf - 1 < fdata.sz)
							goto fail_too_long;
						fdata.buf[fdata.sz++] = *col++;
					}
					fdata.buf[fdata.sz++] = '\0';
				}

				if (*col) {
					/* We use structured parameters instead of title. */
					error->error.msg = "Trailing characters"; /* Fuck users, live long Vim. */
					goto fail;
				}
			} else if (IS_DIRECTIVE("EXT-X-BASE-URL:")) {
				if (0 < playlist->nfiles) {
				fail_used_too_late:
					error->error.msg = "Directive may only be used before media URLs";
					goto fail;
				}

				Playlist *parent = playlist_get_parent(playlist);

				close(playlist->dirfd);
				playlist->dirfd = opendirat(parent->dirfd, col);

				/* NOTE: Only plain directory base URLs are supported. */
				if (playlist->dirfd < 0) {
					error->error.msg = "Cannot open directory of playlist";
					goto fail;
				}
			} else if (IS_DIRECTIVE("PLAYLIST:")) {
				if (0 < playlist->nfiles)
					goto fail_used_too_late;

				free(playlist->name);
				if (!(playlist->name = strdup(col)))
					goto fail_enomem;
			} else {
				playlist->read_only = 1;
			}

#undef IS_DIRECTIVE
		} else if (*line) {
			char const *url = line;
			size_t urlsz = line_end - line + 1 /* NUL */;

			if (sizeof fdata.buf < urlsz + (fdata.sz - 1 /* Reserved */))
				goto fail_too_long;

			enum FileType type = playlist_probe_url(NULL, url);
			File *f = playlist_alloc_file(playlist, type, urlsz + (fdata.sz - 1));
			if (!f)
				goto fail_enomem;

			for (enum Metadata i = 0; i < M_NB; ++i)
				f->metadata[i] = fdata.f.metadata[i]
					? urlsz + fdata.f.metadata[i] - 1
					: 0;

			memcpy(f->url, url, urlsz);
			memcpy(f->url + urlsz, fdata.buf + 1, fdata.sz - 1);

			file_read(f, error);
			fdata_reset(&fdata, 1);
		}

		++line_end; /* Skip LF. */
		bufsz -= line_end - line;
		line = line_end;
		++lnum;
	}

out:
	close(fd);
	return;

fail_enomem:
	error_from_strerror(&error->error, ENOMEM);
fail:
	error->lnum = lnum;
	error->col = col ? (size_t)(col - buf) + 1 : 0;
	assert(!error_is_ok(&error->error));
	goto out;
}

static char *
path_join(char const *base, char const *name)
{
	if ('/' == *name)
		return strdup(name);

	while ('.' == name[0] && '/' == name[1])
		name += 2;

	for (; '.' == base[0]; base += 2) {
		if ('/' == base[1])
			continue;

		if (!base[1])
			return strdup(name);
		break;
	}

	int n = snprintf(NULL, 0, "%s/%s", base, name);
	char *ret = malloc(n + 1 /* NUL */);
	if (!ret)
		return NULL;
	sprintf(ret, "%s/%s", base, name);
	return ret;
}

void
playlist_free(Playlist *playlist)
{
	if (0 <= playlist->dirfd)
		close(playlist->dirfd);
	free(playlist->dirname);
	free(playlist->name);
	free(playlist);
	/* TODO: Implement. */
}

void
playlists_destroy(void)
{
	for (int16_t i = 0; i < nplaylists; ++i)
		playlist_free(playlists[i]);
}

Playlist *
playlist_alloc_master(void)
{
	Playlist *playlist = playlist_alloc(NULL, "master");
	if (!playlist)
		return NULL;
	playlist->read_only = 1;
	playlist->dirname = strdup(".");
	if (!playlist->dirname) {
		playlist_free(playlist);
		return NULL;
	}
	playlist->dirfd = opendirat(AT_FDCWD, playlist->dirname);
	return playlist;
}

Playlist *
playlist_alloc(File const *f, char const *name)
{
	assert(!f || F_FILE < f->type);

	if (arrayrealloc_pow2(&playlists, nplaylists, sizeof *playlists))
		return NULL;

	Playlist *playlist = malloc(sizeof *playlist);
	char *s = strdup(name);
	if (!playlist || !s) {
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

File *
playlist_alloc_file_dupurl(Playlist *parent, enum FileType type, char const *url)
{
	size_t sz = strlen(url) + 1 /* NUL */;
	File *f = playlist_alloc_file(parent, type, sz);
	if (f)
		memcpy(f->url, url, sz);
	return f;
}

File *
playlist_alloc_file(Playlist *parent, enum FileType type, size_t urlsz)
{
	if (arrayrealloc_pow2(&files, nfiles[FILTER_ALL], sizeof *files))
		return NULL;

	File *f = malloc(sizeof *f);
	char *url = malloc(urlsz);
	if (!f || !url) {
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

	files_dirty_batch();

	return f;
}

static void
playlist_save(Playlist *playlist, Error *error)
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

	int dirfd = playlist_get_parent(playlist)->dirfd;
	if (safe_sprintf(tmp, "%s~", playlist->f->url) < 0 ||
	    (fd = openat(dirfd, tmp, O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, 0666)) < 0)
	{
		error_msg = "Cannot open temporary playlist file";
		return;
	}

	if (F_PLAYLIST_COMPRESSED == playlist->f->type)
		playlist_pipe_compress(playlist, &fd, &pid, 1);

	stream = fdopen(fd, "w");
	if (!stream) {
		error_msg = "Cannot open playlist stream";
		goto out;
	}
	fd = -1;

	char buf[UINT16_MAX + 1];
	setbuffer(stream, buf, sizeof buf);

	playlist_write_m3u(playlist, stream);

	if (fflush(stream), ferror(stream)) {
		error_msg = "Cannot write playlist";
		goto out;
	}

	fclose(stream);
	stream = NULL;

	if (0 <= pid) {
		int rc = reap(pid);
		pid = -1;
		if (rc < 0) {
			error_msg = "Compressor failed";
			goto out;
		}
	}

	if (renameat(dirfd, tmp, dirfd, playlist->f->url) < 0) {
		error_msg = "Cannot rename playlist";
		goto out;
	}
	*tmp = '\0';

	playlist->modified = 0;

out:
	if (error_msg)
		error_setf(error, "Cannot save playlist: %s: %s",
				playlist->name, error_msg);

	if (*tmp)
		unlink(tmp);

	if (0 <= fd)
		close(fd);

	if (stream)
		fclose(stream);

	if (0 <= pid)
		(void)reap(pid);
}

void
playlists_save(Error *error)
{
	qsort(files, nfiles[FILTER_ALL], sizeof *files, file_playlist_order_cmp);

	for (int16_t i = 0; i < nplaylists; ++i)
		playlist_save(playlists[i], error);
}

Playlist *
playlist_get_parent(Playlist const *playlist)
{
	return file_get_playlist(playlist->f);
}

void
playlist_write_m3u(Playlist *playlist, FILE *stream)
{
	fprintf(stream, "#EXTM3U\n");
	if (playlist->name)
		fprintf(stream, "#PLAYLIST:%s\n", playlist->name);

	for (int32_t i = 0; i < nfiles[FILTER_ALL]; ++i) {
		File const *f = files[i];
		if (playlist->index != f->playlist_index)
			continue;

		if (f->type <= F_FILE)
			file_write_m3u(f, stream);
		fprintf(stream, "%s\n", f->url);
	}
}

void
playlist_read(Playlist *playlist, int fd, FileReadError *error)
{
	Playlist *parent = playlist_get_parent(playlist);

	switch (playlist->f->type) {
	case F_PLAYLIST:
	case F_PLAYLIST_COMPRESSED:
	{
		char *slash = strrchr(playlist->f->url, '/');
		if (slash)
			*slash = '\0';
		char const *dirname = slash ? playlist->f->url : ".";

		playlist->dirfd = opendirat(parent->dirfd, dirname);
		playlist->dirname = path_join(parent->dirname, dirname);

		if (slash)
			*slash = '/';

		if (playlist->dirfd < 0) {
			error_from_errno(&error->error);
			close(fd);
			return;
		}

		pid_t pid = -1;
		if (F_PLAYLIST_COMPRESSED == playlist->f->type)
			playlist_pipe_compress(playlist, &fd, &pid, 0);

		playlist_read_m3u(playlist, fd, error);

		if (0 <= pid && reap(pid) < 0)
			error_setf(&error->error, "Decompressor failed");

		if (!error_is_ok(&error->error)) {
			/* Try do our best, so just mark it as read-only. This avoids
			 * writing back any faulty data. */
			playlist->read_only = 1;
		}
	}
		break;

	case F_PLAYLIST_DIRECTORY:
		playlist->dirfd = fd;
		playlist->dirname = path_join(parent->dirname, playlist->f->url);
		playlist->read_only = 1;
		playlist_read_dir(playlist, error);
		break;

	default:
		abort();
	}
}

enum FileType
playlist_probe_url(Playlist const *parent, char const *url)
{
	char const *colon = strchr(url, ':');
	if (colon && colon < strchr(url, '/'))
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

