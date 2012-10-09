#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <errno.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <assert.h>
#include <pthread.h>
#include <signal.h>


#define SA struct sockaddr_in

#define BOOL unsigned int
#define FALSE 0
#define TRUE 1

#define UINT unsigned int

#define WRITE_PIPE_FD 1
#define READ_PIPE_FD 0

#define ECHO_SERVICE_PORT 11811
#define TIME_SERVICE_PORT 11812
// TODO Fix this
#define TIME_SERVER_SLEEP_SEC 2
#define TIME_SERVER_SLEEP_USEC 0

#define SRV_LISTENQ 100

#define MAXMSGLEN 500
#define MAXLEN 5000

struct client_info {
  int sockfd;
  char *read_buf;
  int buf_len;
  UINT read_ptr;
};

void err_sys(char *str);
BOOL is_ip_address(char *str);
UINT min(UINT a, UINT b);
UINT max(UINT a, UINT b);
void read_into_buf(struct client_info *cli, UINT max_len);
int buffered_readline(struct client_info *cli, char *target_buf, UINT len);
char *get_err_str(char *s);
#endif
