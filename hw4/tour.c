// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "unp.h"
#include <linux/if_ether.h>

int rt, pg, pf, udp;
vector tour_hosts;  // List of hostnames that we have to visit, excluding us.
ipaddr_ascii myip;  // TODO Populate this
tour_list tour;     // TODO Populate this (also add myip to the list)
bool visited;       // Whether this node has been touched by a tour

void tour_setup(void) {
  const int yes = 1;
  rt = Socket(AF_INET, SOCK_RAW, IPPROTO_HW);
  Setsockopt(rt, SOL_SOCKET, IP_HDRINCL, &yes, sizeof(yes));
  pg = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  pf = Socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
  udp = Socket(AF_INET, SOCK_DGRAM, 0); // FIXME Fix the protocol
  
  vector_init(&tour_hosts, sizeof(char *));
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
  if (argc > 1) {
    // TODO Push your own host-name
    for (i = 1; i < argc; i++) {
      vector_push_back(&tour_hosts, argv[1]);
    }
  } else {
  }
}
