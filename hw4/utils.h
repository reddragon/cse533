// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include "myassert.h"
#include "unp.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>      
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/icmp.h>


#define IPPROTO_HW  0x73
#define ID_NUM      0x60061E5
#define FALSE       0
#define TRUE        1

typedef unsigned char byte;
typedef int bool;

#define OFFSETOF(TYPE,MEMBER) ((int)&((TYPE*)0)->MEMBER)

#define TIMESTAMPMSG(TYPE, X, VARGS...) {     \
  fprintf(stdout, TYPE ": " X, VARGS);        \
  fflush(stdout);                             \
}

// FIXME Change to DEBUG
#if 1
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

#define ETHERNET_PAYLOAD_SIZE 60

typedef struct eth_frame {
  eth_addr_n dst_eth_addr;  // Destination Ethernet Address
  eth_addr_n src_eth_addr;  // Source Ethernet Address
  uint16_t protocol;        // Protocol
  char payload[ETHERNET_PAYLOAD_SIZE];       // Payload
} eth_frame;

typedef struct ip_icmp_hdr_t {
  eth_addr_n dst_eth_addr;  // Destination Ethernet Address
  eth_addr_n src_eth_addr;  // Source Ethernet Address
  uint16_t protocol;        // Protocol

  struct iphdr iphdr;
  struct icmphdr icmphdr;
  char icmpdata[0];
} ip_icmp_hdr_t;


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
  uint16_t  current_node_idx;
  ipaddr_n  mcast_addr;
  int       mcast_port;
  tour_list tour;
} tour_pkt;

void utils_init(void);
uint32_t current_time_in_ms(void);
char *create_tmp_file(void);
void send_over_ethernet(int sockfd, eth_frame *ef,
                        int size, int sll_ifindex);
void* my_malloc(size_t size);
eth_addr_ascii pp_eth(char hwaddr[6]);
char *pp_ip(ipaddr_n ipaddr, char *buf, size_t buflen);
char *hostname_to_ip_address(const char *hostname, char *ip);
char *ip_address_to_hostname(const char *ip, char *hostname);
struct hwa_info * Get_hw_addrs(void);
#endif

