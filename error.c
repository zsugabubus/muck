#include "regex.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#if WITH_ICU
# include <unicode/utypes.h>
#endif

#include "error.h"

void
error_reset(Error *error)
{
	error->msg = NULL;
}

int
error_is_ok(Error const *error)
{
	return !error->msg;
}

void
error_setf(Error *error, char const *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	error->msg = error->buf;
	vsnprintf(error->buf, sizeof error->buf, msg, ap);
	va_end(ap);
}

void
error_setf_strerror(Error *error, char const *msg, ...)
{
	int err = errno;

	va_list ap;
	va_start(ap, msg);
	error->msg = error->buf;
	int n = vsnprintf(error->buf, sizeof error->buf, msg, ap);
	if (n < (int)sizeof error->buf)
		snprintf(error->buf + n, sizeof error->buf - n,
				": %s", strerror(err));
	va_end(ap);
}

void
error_from_errno(Error *error)
{
	error_from_strerror(error, errno);
}

void
error_from_strerror(Error *error, int errnum)
{
	error->msg = strerror(errnum);
}

void
error_from_regerror(Error *error, int error_code)
{
	pcre2_get_error_message(error_code,
			(uint8_t *)error->buf,
			sizeof error->buf);
	error->msg = error->buf;
}

void
error_from_icu_error(Error *error, UErrorCode error_code)
{
	error->msg = u_errorName(error_code);
}

void
error_ok_or_die(Error *error, char const *msg)
{
	if (error_is_ok(error))
		return;

	fprintf(stderr, "%s: %s\n", msg, error->msg);
	exit(EXIT_FAILURE);
}
