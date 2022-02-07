#include "stdio_utils.h"
#include <stdlib.h>
#include <unistd.h>

#include "env.h"

char config_home[PATH_MAX];
char cover_path[PATH_MAX];

void
env_init(Error *error)
{
	char const *env;

	if ((env = getenv("MUCK_HOME"))) {
		if (safe_sprintf(config_home, "%s", env))
			goto fail_too_long;
	} else {
		if ((env = getenv("XDG_CONFIG_HOME"))) {
			if (safe_sprintf(config_home, "%s/muck", env))
				goto fail_too_long;
		} else if ((env = getenv("HOME"))) {
			if (safe_sprintf(config_home, "%s/.config/muck", env))
				goto fail_too_long;

			if (access(config_home, F_OK))
				if (safe_sprintf(config_home, "%s/.muck", env))
					goto fail_too_long;
		} else {
			error->msg = "Cannot determine $MUCK_HOME";
			return;
		}

		if (setenv("MUCK_HOME", config_home, 1))
			goto fail_strerror;
	}

	if ((env = getenv("MUCK_COVER"))) {
		if (safe_sprintf(cover_path, "%s", env))
			goto fail_too_long;
	} else {
		if ((env = getenv("XDG_RUNTIME_DIR"))) {
			if (safe_sprintf(cover_path, "%s/muck-cover", env))
				goto fail_too_long;
		} else {
			if (!(env = getenv("TMPDIR")))
				env = "/tmp";
			if (safe_sprintf(cover_path, "%s/muck-%ld-cover", env, (long)getuid()))
				goto fail_too_long;
		}

		if (setenv("MUCK_COVER", cover_path, 1))
			goto fail_strerror;
	}

	return;

fail_too_long:
	error->msg = "Environment variable is too long";
	return;

fail_strerror:
	error_from_errno(error);
	return;
}

