#ifndef _UTILS_H_
#define _UTILS_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "unpifiplus.h"

#define UINT unsigned int
#define BOOL unsigned short

struct client_args {
  char ip_addr[20];
  UINT serv_portno;
  char file_name[100];
  UINT sw_size;
  UINT rand_seed;
  double p; // Prob. of packet loss
  double mean; // Mean
};

int read_cargs(char *cargs_file, struct client_args *cargs);
struct ifi_info * Get_ifi_info_plus(int family, int doaliases);
void print_ifi_info(struct ifi_info *ifi);
#endif
