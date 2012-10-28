#ifndef PERHAPS_H
#define PERHAPS_H

#include "perhaps.h"
#include "utils.h"
#include <stdlib.h>

// These functions are used only by the client since only the client
// behaves erratically.

extern struct client_args *cargs;

void perhaps_init(void) {
    srandom(cargs->rand_seed);
}

int perhaps_send(int fd, const void *data, int len, int flags) {
    double rn = ((double)random()) / (double)(RAND_MAX);
    if (rn <= cargs->p) {
        // Silently drop the packet.
        return len;
    }
    // Actually send the data.
    int r = send(fd, data, len, flags);
    return r;
}

int perhaps_recv(int fd, void *data, int len, int flags) {
    double rn = ((double)random()) / (double)(RAND_MAX);
    int r = recv(fd, data, len, flags);
    if (rn <= cargs->p) {
        // Silently discard the received data.
        errno = EINTR;
        return -1;
    }
    return r;
}

int perhaps_recvfrom(int fd, void *data, int len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
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
