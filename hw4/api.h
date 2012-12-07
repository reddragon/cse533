// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _API_H_
#define _API_H_

#include "utils.h"
#include <sys/socket.h>
#include <sys/un.h>

// The sun_path for the ARP server
#define SRV_SUNPATH "/tmp/dynamic_duo/arp_serv"

typedef struct hwaddr {
  int             sll_ifindex;  /* Interface number */
  unsigned short  sll_hatype;   /* Hardware type */
  unsigned char   sll_halen;    /* Length of address */
  unsigned char   sll_addr[8];  /* Physical layer address */
} hwaddr;

typedef struct api_msg {
  eth_addr_n      eth_addr; 
  ipaddr_n        ipaddr_nw;
  int             sll_ifindex;
  unsigned short  sll_hatype;
  unsigned char   sll_halen;
} api_msg;

int areq(ipaddr_ascii ipaddr, struct hwaddr *hwaddr);

#endif

