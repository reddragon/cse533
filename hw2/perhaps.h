#ifndef PERHAPS_H
#define PERHAPS_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

// These functions are used only by the client since only the client
// behaves erratically.

void perhaps_init(void);
#ifdef DEBUG
int perhaps_rarely_send(int fd, const void *data, int len, int flags);
#endif
int perhaps_send(int fd, const void *data, int len, int flags);
int perhaps_recv(int fd, void *data, int len, int flags);
int perhaps_recvfrom(int fd, void *data, int len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);

#endif // PERHAPS_H
