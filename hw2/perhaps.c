#ifndef PERHAPS_H
#define PERHAPS_H

#include "perhaps.h"
#include "utils.h"
#include <stdlib.h>
#include <assert.h>

// These functions are used only by the client since only the client
// behaves erratically.

extern struct client_args *cargs;
static BOOL perhaps_inited = FALSE;

void perhaps_init(void) {
    srand48(cargs->rand_seed);
    perhaps_inited = TRUE;
}

int perhaps_send(int fd, const void *data, int len, int flags) {
    assert(perhaps_inited == TRUE);
    double rn = drand48();
    if (rn <= cargs->p) {
        // Silently drop the packet.
        return len;
    }
    // Actually send the data.
    int r = send(fd, data, len, flags);
    return r;
}

int perhaps_recv(int fd, void *data, int len, int flags) {
    assert(perhaps_inited == TRUE);
    double rn = drand48();
    int r = recv(fd, data, len, flags);
    if (rn <= cargs->p) {
        // Silently discard the received data.
        errno = EINTR;
        return -1;
    }
    return r;
}

int perhaps_recvfrom(int fd, void *data, int len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    assert(perhaps_inited == TRUE);
    double rn = ((double)random()) / (double)(RAND_MAX);
    int r = recvfrom(fd, data, len, flags, src_addr, addrlen);
    if (rn <= cargs->p) {
        // Silently discard the received data.
        errno = EINTR;
        return -1;
    }
    return r;
}

#endif // PERHAPS_H
