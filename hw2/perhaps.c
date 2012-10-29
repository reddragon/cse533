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

extern int recv_total;       // Total calls to recv(2) or recvfrom(2)
extern int recv_failed;      // # of calls to recv(2) or recvfrom(2) that failed
extern int send_total;       // Total calls to send(2)
extern int send_failed;      // # of calls to send(2) that failed

void perhaps_init(void) {
    srand48(cargs->rand_seed);
    perhaps_inited = TRUE;
}

#ifdef DEBUG
int perhaps_rarely_send(int fd, const void *data, int len, int flags) {
    assert(perhaps_inited == TRUE);
    // ++send_total;
    double rn = drand48();
    fprintf(stderr, "perhaps_rarely_send::rn = %.2f\n", rn);
    if (rn <= 0.7) {
        // Silently drop the packet.
        fprintf(stderr, "perhaps_rarely_send::Dropping packet.\n");
        // ++send_failed;
        return len;
    }
    // Actually send the data.
    int r = send(fd, data, len, flags);
    return r;
}
#endif

int perhaps_send(int fd, const void *data, int len, int flags) {
    assert(perhaps_inited == TRUE);
    ++send_total;
    double rn = drand48();
    if (rn <= cargs->p) {
        // Silently drop the packet.
        fprintf(stderr, "perhaps_send::Dropping packet.\n");
        ++send_failed;
        return len;
    }
    // Actually send the data.
    int r = send(fd, data, len, flags);
    return r;
}

int perhaps_recv(int fd, void *data, int len, int flags) {
    assert(perhaps_inited == TRUE);
    double rn = drand48();
    ++recv_total;
    int r = recv(fd, data, len, flags);
    if (rn <= cargs->p) {
        fprintf(stderr, "perhaps_recv::Dropping packet.\n");
        // Silently discard the received data.
        ++recv_failed;
        errno = EINTR;
        return -1;
    }
    return r;
}

int perhaps_recvfrom(int fd, void *data, int len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    assert(perhaps_inited == TRUE);
    double rn = drand48();
    ++recv_total;
    int r = recvfrom(fd, data, len, flags, src_addr, addrlen);
    if (rn <= cargs->p) {
        fprintf(stderr, "perhaps_recvfrom::Dropping packet.\n");
        ++recv_failed;
        // Silently discard the received data.
        errno = EINTR;
        return -1;
    }
    return r;
}

#endif // PERHAPS_H
