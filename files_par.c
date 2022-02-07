#include "assert_utils.h"
#include "atomic_utils.h"
#include "compat/pthread.h"
#include "math_utils.h"
#include <stdint.h>
#include <unistd.h>

#include "config.h"
#include "files.h"
#include "files_par.h"
#include "math_utils.h"

enum {
	FILE_WORKERS_MAX = 64,
};

typedef struct FileTask FileTask;
struct FileWorker {
	FileTask *task;
	int32_t cur;
	int32_t end;
	pthread_t thread;
	void const *arg;
};

struct FileTask {
	int32_t cur;
	int32_t end;
	int32_t batch_size;
	long nworkers;
	int (*routine)(FileWorker *, void const *);
	FileWorker workers[FILE_WORKERS_MAX];
};

static long ncpus;

static void *
files_par_trampoline(void *arg)
{
	FileWorker *worker = arg;

#if HAVE_PTHREAD_SETNAME_NP
	char name[16];
	snprintf(name, sizeof name, "muck/worker%zu",
			(size_t)(worker - worker->task->workers));
	pthread_setname_np(pthread_self(), name);
#endif

	return (void *)(intptr_t)worker->task->routine(worker, worker->arg);
}

void
files_par_init(void)
{
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	ncpus = MAXMIN(1, ncpus, FILE_WORKERS_MAX);
}

int
files_par_iter(int (*routine)(FileWorker *, void const *), void const *arg)
{
	static int32_t const BATCH_SIZE_MIN = 16;
	static int32_t const BATCH_SIZE_MAX = 256;

	FileTask task;

	task.routine = routine;
	task.cur = 0;
	task.end = nfiles[FILTER_ALL];
	if (1 < ncpus) {
		task.batch_size = MAXMIN(
			BATCH_SIZE_MIN,
			task.end / ncpus,
			BATCH_SIZE_MAX);
	} else {
		task.batch_size = task.end;
	}

	if (task.batch_size) {
		task.nworkers = (task.end + task.batch_size - 1) / task.batch_size;
		task.nworkers = MIN(task.nworkers, ncpus);
	} else {
		task.nworkers = 0;
	}

	int rc;

	FileWorker *worker = task.workers;
	for (uint8_t i = 0;; ++i) {
		*worker = (FileWorker){
			.task = &task,
			.arg = arg,
		};

		if (i + 1 < task.nworkers &&
		    0 <= pthread_create(&worker->thread, NULL, files_par_trampoline, worker))
		{
			++worker;
		} else {
			rc = task.routine(worker, arg);
			break;
		}
	}

	while (task.workers <= --worker)
		xassert(!pthread_join(worker->thread, NULL));

	return task.end <= task.cur ? 0 : (assert(rc < 0), rc);
}

File *
files_par_next(FileWorker *worker)
{
	if (worker->end <= worker->cur) {
		FileTask *task = worker->task;
		/* NOTE: May overflow if we would have lot's of workers. */
		worker->cur = atomic_fetch_add_lax(&task->cur, task->batch_size);
		worker->end = MIN(worker->cur + task->batch_size, task->end);
		if (worker->end <= worker->cur)
			return NULL;
	}

	return files[worker->cur++];
}
