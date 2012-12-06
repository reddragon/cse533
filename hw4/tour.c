// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "unp.h"
#include <linux/if_ether.h>

int rt, pg, pf, udp; // rt -> Routing; pg -> Ping; pf -> PF Packet; udp -> For Multicast
vector tour_hosts;   // List of hostnames that we have to visit, excluding us.
ipaddr_ascii myip_a; // My IP address in presentation format
ipaddr_n     myip_n; // My IP address in network byte order
tour_list tour;      // List of IP addresses (in network
                     // order). Includes my own IP address.
bool visited;        // Whether this node has been touched by a tour
fdset fds;           // List of FDs to wait on

struct hostname_t {
  char hostname[60];
} hostname_t;

void tour_setup(int argc, char *argv[]) {
  const int yes = 1;
  int i;
  rt = Socket(AF_INET, SOCK_RAW, IPPROTO_HW);
  Setsockopt(rt, SOL_SOCKET, IP_HDRINCL, &yes, sizeof(yes));
  pg = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  pf = Socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
  udp = Socket(AF_INET, SOCK_DGRAM, 0); // FIXME Fix the protocol
  
  vector_init(&tour_hosts, sizeof(hostname_t));
  hostname_t hn;

  // TODO: Get my eth0 IP address.
  strcpy(hn.hostname, myip);

  vector_push_back(&tour_hosts, &hn);

  for (i = 1; i < argc; i++) {
    strcpy(hn.hostname, argv[i]);
    vector_push_back(&tour_hosts, &hn);
  }
}

void
act_on_pkt(ip_pkt *pkt) {
  /*
    if (pkt->id != ID_NUM) {
    // TODO Add message
    return;
   }
   if (!visited) {
   // TODO Join Multicast
   visited = TRUE;
   }
  */
}

int
main(int argc, char **argv) {
  int i;
}
