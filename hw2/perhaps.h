#ifndef PERHAPS_H
#define PERHAPS_H

#include "utils.h"
#include <stdlib.h>

// These functions are used only by the client since only the client
// behaves erratically.

extern struct client_args cargs;

void perhaps_init(void);
int perhaps_send(int fd, const void *data, int len, int flags);
int perhaps_recv(int fd, void *data, int len, int flags);
int perhaps_recvfrom(int fd, void *data, int len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);

#endif // PERHAPS_H
