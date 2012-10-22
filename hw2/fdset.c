#include "fdset.h"

void fdset_init(fdset *fds) {
    FD_ZERO(&fds->rfds);
    FD_ZERO(&fds->exfds);
    FD_ZERO(&fds->wfds);
    fds->max_fd = -1;
}

void fdset_add_all(fdset *fds, fd_set *fset, vector *v) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        int fd = *(int*)(vector_at(v, i));
        FD_SET(fd, fset);
        fds->max_fd = (fd > fds->max_fd ? fd : fds->max_fd);
    }
}
