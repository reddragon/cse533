#ifndef _UTILS_H_
#define _UTILS_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "unpifiplus.h"

#define UINT unsigned int
#define BOOL unsigned short
#define FALSE 0
#define TRUE 1
#define MALLOC(X) (X *) malloc(sizeof(X) * 1)

#define CARGS_FILE "client.in"
#define SARGS_FILE "server.in"
#define MAXSOCKS 100

struct client_args {
  char ip_addr[20];
  UINT serv_portno;
  char file_name[100];
  UINT sw_size;
  UINT rand_seed;
  double p; // Prob. of packet loss
  double mean; // Mean
};

struct client_conn {
  struct sockaddr *serv_sa;
  struct sockaddr *cli_sa;
  BOOL is_local; // Is the server local?
};

struct server_conn {
  struct sockaddr *serv_sa;
  struct sockaddr *cli_sa;
  BOOL is_local; // Is the client local?
};

struct server_args {
  UINT serv_portno;
  UINT sw_size;
};

int read_cargs(char *cargs_file, struct client_args *cargs);
int read_sargs(char *sargs_file, struct server_args *sargs);
struct ifi_info * Get_ifi_info_plus(int family, int doaliases);
void print_ifi_info(struct ifi_info *ifi);
struct sockaddr* get_subnet_addr(struct sockaddr *addr, struct sockaddr *ntm);
char *sa_data_str(struct sockaddr *sa);
UINT get_ntm_len(struct sockaddr *ntm);
struct sockaddr *inet_pton_sa(const char *ip_addr, UINT portno);
#endif
