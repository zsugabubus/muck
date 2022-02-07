#ifndef MUCK_ENV_H
#define MUCK_ENV_H

#include <limits.h>

#include "error.h"

void env_init(Error *error);

extern char config_home[PATH_MAX];
extern char cover_path[PATH_MAX];

#endif
