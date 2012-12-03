#ifndef _API_H_
#define _API_H_

#include "utils.h"

#define SRV_SUNPATH "/tmp/dynamic_duo/arp_serv"

typedef struct hwaddr {
  int             sll_ifindex;  /* Interface number */
  unsigned short  sll_hatype;   /* Hardware type */
  unsigned char   sll_halen;    /* Length of address */
  unsigned char   sll_addr[8];  /* Physical layer address */
} hwaddr;

typedef struct api_msg {
  ipaddr_p ipaddr;
} api_msg;

int areq(struct sockaddr *ipaddr, socklen_t slen, struct hwaddr *hwaddr);

#endif

