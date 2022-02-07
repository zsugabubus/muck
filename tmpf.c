#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "error.h"
#include "tmpf.h"
#include "tui.h"

FILE *
tmpf_open(TemporaryFile *tmpf, Error *error)
{
	char const *tmpdir = getenv("TMPDIR");
	if (!tmpdir)
		tmpdir = "/tmp";

	int n = snprintf(tmpf->pathname, sizeof tmpf->pathname,
			"%s/muckXXXXXX", tmpdir);
	if (PATH_MAX <= n)
		goto fail;

	int fd = mkostemp(tmpf->pathname, O_CLOEXEC);
	if (fd < 0)
		goto fail;

	FILE *ret = fdopen(fd, "w");
	if (!ret) {
		close(fd);
		goto fail;
	}

	return ret;

fail:
	error_setf(error, "Cannot create temporary file");
	return NULL;
}

void
tmpf_close(TemporaryFile *tmpf)
{
	unlink(tmpf->pathname);
}

FILE *
tmpf_edit(TemporaryFile *tmpf)
{
	FILE *stream = NULL;

	int rc = tui_shellout();
	if (!rc) {
		char const *editor = getenv("EDITOR");
		execlp(editor, editor, "--", tmpf->pathname, NULL);
		_exit(EXIT_FAILURE);
	} else if (0 < rc) {
		stream = fopen(tmpf->pathname, "re");
	}

	tmpf_close(tmpf);

	return stream;
}

char *
tmpf_readline(TemporaryFile *tmpf)
{
	char *ret = NULL;

	FILE *stream = tmpf_edit(tmpf);
	if (stream) {
		size_t sz = 0;
		ssize_t len = getline(&ret, &sz, stream);
		if (len < 0) {
			free(ret);
			ret = NULL;
		} else if (0 < len && '\n' == ret[len - 1])
			ret[len - 1] = '\0';

		fclose(stream);
	}

	return ret;
}
