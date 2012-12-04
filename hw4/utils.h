// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _UTILS_H_
#define _UTILS_H_

#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>      
#include <linux/if.h>
#include <assert.h>
#include "myassert.h"
#include "unp.h"

#define IPPROTO_HW  0x8086
#define ID_NUM      0x60061E5
#define FALSE       0
#define TRUE        1

typedef unsigned char byte;
typedef int bool;

#define TIMESTAMPMSG(TYPE, X, VARGS...) {     \
  fprintf(stdout, TYPE ": " X, VARGS);        \
  fflush(stdout);                             \
}

#ifdef DEBUG
#define VERBOSE(X, VARGS...) TIMESTAMPMSG("VERBOSE", X, VARGS)
#else
#define VERBOSE(X...)
#endif

#define INFO(X, VARGS...) TIMESTAMPMSG("INFO", X, VARGS)
#define MALLOC(X) (X *) my_malloc(sizeof(X))
#define NMALLOC(X,N) (X *) my_malloc(sizeof(X) * N)

void* my_malloc(size_t size);


// IP Address in ASCII (presentation) format
typedef struct ipaddr_ascii {
  char addr[16];
} ipaddr_ascii;

// IP Address in Network Notation
// use struct in_addr;
typedef struct in_addr ipaddr_n;

typedef struct ip_pkt {
  ipaddr_n dst_ip;
  ipaddr_n src_ip;
} ip_pkt;

// The ethernet address in Network Notation
typedef struct eth_addr_n {
    char addr[6];
} eth_addr_n;

// The ethernet address in ASCII Notation
typedef struct eth_addr_ascii {
    char addr[20];
} eth_addr_ascii;

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};

// TODO Is there any way out of statically declaring the MAXNODES?
//      The tour_list structure will potentially be sent in the IP
//      packets.
//
// We keep things simple by statically declaring it to be an array of
// 200 elements.
//
#define MAXNODES 200
typedef struct tour_list {
  int num_nodes;
  ipaddr_n nodes[MAXNODES];
} tour_list;

typedef struct tour_pkt {
  tour_list tlist;
  uint16_t tlist_ptr;
  ipaddr_n mcast_addr;
  int mcast_port;
} tour_pkt;

char *create_tmp_file(void);

void* my_malloc(size_t size);
void pretty_print_eth_addr(char hwaddr[6], char *out);
struct hwa_info * Get_hw_addrs(void);
#endif

