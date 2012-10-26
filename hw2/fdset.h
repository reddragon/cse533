#ifndef FDSET_H
#define FDSET_H

#include <sys/types.h>
#include "vector.h"

typedef void (*ev_callback_t) (void*);

typedef struct {
    int fd;
    void *opaque;
    ev_callback_t callback;
} select_event_t;

typedef struct fdset {
    fd_set rfds, exfds, wfds;
    int max_fd;
    vector rev, exev, wev;
    struct timeval timeout;
    ev_callback_t timeout_cb;
} fdset;

void fdset_init(fdset *fds);
void fdset_populate(fdset *fds, fd_set *fset, vector *v);
void fdset_add(fdset *fds, vector *v, int fd, void *opaque, ev_callback_t callback);
int fdset_exists(fdset *fds, vector *v, int fd);
void fdset_remove(fdset *fds, vector *v, int fd);
int fdset_poll(fdset *fds, struct timeval *timeout, ev_callback_t timeout_cb);


#endif // FDSET_H
