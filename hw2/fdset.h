#ifndef FDSET_H
#define FDSET_H

#include <sys/types.h>
#include "vector.h"

typedef struct fdset {
    fd_set rfds, exfds, wfds;
    int max_fd;
} fdset;

void fdset_init(fdset *fds);
void fdset_add_all(fdset *fds, fd_set *fset, vector *v);

#endif // FDSET_H
