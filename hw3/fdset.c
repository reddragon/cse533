#include "fdset.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "algorithm.h"
#include "utils.h"

void fdset_init(fdset *fds, struct timeval timeout, ev_callback_t timeout_cb) {
    FD_ZERO(&fds->rfds);
    FD_ZERO(&fds->exfds);
    FD_ZERO(&fds->wfds);

    fds->max_fd     = -1;
    fds->timeout    = timeout;
    fds->timeout_cb = timeout_cb;

    vector_init(&fds->rev, sizeof(select_event_t));
    vector_init(&fds->exev, sizeof(select_event_t));
    vector_init(&fds->wev, sizeof(select_event_t));
}

void fdset_populate(fdset *fds, fd_set *fset, vector *v) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        select_event_t *pse = (select_event_t*)(vector_at(v, i));
        FD_SET(pse->fd, fset);
        fds->max_fd = (pse->fd > fds->max_fd ? pse->fd : fds->max_fd);
    }
}

void fdset_add(fdset *fds, vector *v, int fd, void *opaque, ev_callback_t callback) {
    select_event_t se;
    se.fd = fd;
    se.opaque = opaque;
    se.callback = callback;

    fdset_remove(fds, v, fd);
    vector_push_back(v, &se);
}

int fdset_exists(fdset *fds, vector *v, int fd) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        select_event_t *pse = (select_event_t*)vector_at(v, i);
        if (pse->fd == fd) {
            return 1;
        }
    }
    return 0;
}

void fdset_remove(fdset *fds, vector *v, int fd) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        select_event_t *pse = (select_event_t*)vector_at(v, i);
        if (pse->fd == fd) {
            vector_erase(v, i);
            --i;
        }
    }
}

int find_by_fd(const void *lhs, const void *rhs) {
    int fd;
    select_event_t *pse;
    fd = *(int*)lhs;
    pse = (select_event_t*)rhs;
    return fd == pse->fd;
}

int fdset_poll(fdset *fds, struct timeval *timeout, ev_callback_t timeout_cb) {
    struct timeval to;
    if (timeout) {
        to = *timeout;
    }
    while (1) {
        FD_ZERO(&fds->rfds);
        FD_ZERO(&fds->exfds);
        FD_ZERO(&fds->wfds);
        fds->max_fd = -1;

        if (vector_empty(&fds->rev) && vector_empty(&fds->exev) && !timeout) {
            // We have nothing left to select(2) on.
            return 0;
        }

        fdset_populate(fds, &fds->rfds, &fds->rev);
        fdset_populate(fds, &fds->exfds, &fds->exev);

        if (timeout) {
            *timeout = to;
        }

        int r = select(fds->max_fd+1, &fds->rfds, 0, &fds->exfds, timeout);
        if (r < 0) {
            if (errno != EINTR) {
                perror("select");
                return r;
            }
            continue;
        }
        if (r == 0) {
            // Timeout case
            timeout_cb(NULL);
            continue;
        }
        int i;
        for (i = 0; i < vector_size(&fds->rev); ++i) {
            select_event_t *pse = (select_event_t*)vector_at(&fds->rev, i);
            if (FD_ISSET(pse->fd, &fds->rfds)) {
                VERBOSE("FD %d is read ready\n", pse->fd);
                pse->callback(pse->opaque);
            }
        }
        for (i = 0; i < vector_size(&fds->exev); ++i) {
            select_event_t se = *(select_event_t*)vector_at(&fds->exev, i);
            if (FD_ISSET(se.fd, &fds->exfds)) {
                INFO("FD %d is in ERROR\n", se.fd);
                // Also remove this fd from the list of ex/read events
                // to monitor.
                vector_erase(&fds->exev, i);
                --i;
                // Remove from read events list as well.
                int rev_pos = algorithm_find(&fds->rev, &se.fd, find_by_fd);
                if (rev_pos != -1) {
                    vector_erase(&fds->rev, rev_pos);
                }
                se.callback(se.opaque);

            } // if ()

        } // for ()

    } // while (1)

} // fdset_poll()

int fdset_poll2(fdset *fds) {
    int r, i;
    while (1) {
        FD_ZERO(&fds->rfds);
        FD_ZERO(&fds->exfds);
        FD_ZERO(&fds->wfds);
        fds->max_fd = -1;

        if (vector_empty(&fds->rev) && vector_empty(&fds->exev)) {
            // We have nothing left to select(2) on.
            return 0;
        }

        fdset_populate(fds, &fds->rfds, &fds->rev);
        fdset_populate(fds, &fds->exfds, &fds->exev);

        r = select(fds->max_fd+1, &fds->rfds, 0, &fds->exfds, &fds->timeout);
        if (r < 0) {
            if (errno != EINTR) {
                perror("select");
                return r;
            }
            continue;
        }
        if (r == 0) {
            // Timeout case
            fds->timeout_cb(NULL);
            continue;
        }
        for (i = 0; i < vector_size(&fds->rev); ++i) {
            select_event_t *pse = (select_event_t*)vector_at(&fds->rev, i);
            if (FD_ISSET(pse->fd, &fds->rfds)) {
                VERBOSE("FD %d is read ready\n", pse->fd);
                pse->callback(pse->opaque);
            }
        }
        for (i = 0; i < vector_size(&fds->exev); ++i) {
            int rev_pos;
            select_event_t se;
            se = *(select_event_t*)vector_at(&fds->exev, i);
            if (FD_ISSET(se.fd, &fds->exfds)) {
                INFO("FD %d is in ERROR\n", se.fd);
                // Also remove this fd from the list of ex/read events
                // to monitor.
                vector_erase(&fds->exev, i);
                --i;
                // Remove from read events list as well.
                rev_pos = algorithm_find(&fds->rev, &se.fd, find_by_fd);
                if (rev_pos != -1) {
                    vector_erase(&fds->rev, rev_pos);
                }
                se.callback(se.opaque);

            } // if ()

        } // for ()

    } // while (1)

} // fdset_poll2()
