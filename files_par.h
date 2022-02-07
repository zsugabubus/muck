#ifndef MUCK_FILES_PAR_H
#define MUCK_FILES_PAR_H

typedef struct File File;
typedef struct FileWorker FileWorker;

void files_par_init(void);
int files_par_iter(int (*routine)(FileWorker *, void const *), void const *arg);
File *files_par_next(FileWorker *);

#endif
