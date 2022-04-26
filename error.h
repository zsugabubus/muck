#ifndef MUCK_ERROR_H
#define MUCK_ERROR_H

typedef struct Error {
	char const *msg;
	char buf[256];
} Error;

void error_reset(Error *error);
int error_is_ok(Error const *error);

void error_setf(Error *error, char const *msg, ...);
void error_setf_strerror(Error *error, char const *msg, ...);

void error_from_strerror(Error *error, int errnum);
void error_from_errno(Error *error);
void error_from_regerror(Error *error, int error_code);

typedef enum UErrorCode UErrorCode;
void error_from_icu_error(Error *error, UErrorCode error_code);

void error_ok_or_die(Error *error, char const *msg);

#endif
