#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "rnd.h"

int
rnd_init(RndState *state)
{
	int fd = open("/dev/random", O_CLOEXEC | O_EXCL | O_RDONLY);
	if (fd < 0)
		return fd;

	int rc = 0;

	do {
		size_t rem = sizeof state->bytes;
		do {
			ssize_t got = read(fd, (&state->bytes)[1] - rem, rem);
			if (got < 0) {
				rc = -errno;
				goto out;
			} else if (!got) {
				rc = -EBADF;
				goto out;
			}
			rem -= got;
		} while (rem);
		/* Ensure not all zero. */
	} while (!(state->a | state->b));

out:
	close(fd);

	return rc;
}

uint64_t
rnd_next(RndState *state)
{
	uint64_t t = state->a;
	uint64_t s = state->b;
	state->a = s;
	t ^= t << 23;
	t ^= t >> 17;
	t ^= s ^ (s >> 26);
	state->b = t;
	return t + s;
}

uint64_t
rnd_nextn(RndState *state, uint64_t n)
{
	uint64_t rem = UINT64_MAX % n;
	uint64_t x;
	while ((x = rnd_next(state)) < rem);
	return (x - rem) % n;
}
