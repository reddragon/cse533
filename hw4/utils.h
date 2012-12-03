#ifndef _UTILS_H_
#define _UTILS_H_

#define IPPROTO_HW  0x8086
#define ID_NUM      0x60061E5
#define BOOL        0
#define TRUE        1
typedef unsigned char byte;
typedef unsigned char bool;

// IP Address in ASCII Notation
typedef struct ipaddr_a {
  char addr[16]
} ip_addr_p;

// IP Address in Network Notation
typedef struct ipaddr_n {
  unsigned int addr;
} ip_addr_n;

typedef struct ip_pkt {
  ipaddr_n dst_ip;
  ipaddr_n src_ip;

} ip_pkt;

// TODO Is there any way out of statically declaring the MAXNODES?
//      The tour_list structure will potentially be sent in the IP
//      packets.
#define MAXNODES 50
typedef struct tour_list {
  ipaddr_p nodes[MAXNODES];
} tour_list;

typedef struct tour_pkt {
  tour_list tlist;
  uint16_t tlist_ptr;
  ipaddr_p mcast_addr;
  int mcast_port;
};

#endif

