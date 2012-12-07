// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "unp.h"
#include "fdset.h"
#include "api.h"
#include <linux/if_ether.h>

int rt, pg, pf, udp; // rt -> Routing
                     // pg -> Ping
                     // pf -> PF Packet
                     // udp -> For Multicast
ipaddr_ascii myip_a; // My IP address in presentation format
ipaddr_n     myip_n; // My IP address in network byte order
tour_list tour;      // List of IP addresses (in network
                     // order). Includes my own IP address.
bool visited;        // Whether this node has been touched by a tour
fdset fds;           // List of FDs to wait on
vector ping_hosts;   // List of hosts to ping every second

typedef struct ping_info_t {
  ipaddr_n ip;
  int last_ping_ms;
  int num_pings;
} ping_info_t;

void
on_timeout(void *opaque) {
  // FIXME: Change to VERBOSE
  INFO("Timed out.%s\n", "");

  // TODO: Send out ping packets.
}

void
populate_myip(void) {
  struct hwa_info *head, *h;
  struct sockaddr *sa;
  bool found = FALSE;
  
  head = Get_hw_addrs();
  for (h = head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0")) {
      sa = (SA *)h->ip_addr;
      strcpy(myip_a.addr, (char *)Sock_ntop_host(sa, sizeof(*sa)));      
      myip_n = ((struct sockaddr_in *)sa)->sin_addr;
      INFO("My IP Address: %s\n", myip_a.addr);
      found = TRUE;
      break;
    }
  }
  assert(found);
}

void
on_rt_recv(void *opaque) {
}

void
on_pg_recv(void *opaque) {
}

void
on_pf_recv(void *opaque) {
}

void
on_udp_recv(void *opaque) {
}

void
on_rt_error(void *opaque) {
}

void
on_pg_error(void *opaque) {
}

void
on_pf_error(void *opaque) {
}

void
on_udp_error(void *opaque) {
}

void tour_setup(int argc, char *argv[]) {
  const int yes = 1;
  int i, r;
  struct in_addr ia;
  char ipaddr_str[200];
  struct timeval timeout;
  struct hwaddr hwaddr;

  populate_myip();

  rt = Socket(AF_INET, SOCK_RAW, htons(IPPROTO_HW));
  // IP_HDRINCL means that the sender MUST include the header while
  // sending out the packet.
  Setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));

  pg = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  pf = Socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
  udp = Socket(AF_INET, SOCK_DGRAM, 0); // FIXME Fix the protocol

  vector_init(&ping_hosts, sizeof(ping_info_t));

  // TODO: Get my eth0 IP address.
  Inet_pton(AF_INET, hostname_to_ip_address(myip_a.addr, ipaddr_str), &ia);
  tour.nodes[0] = ia;
  tour.num_nodes = 1;

  for (i = 1; i < argc; i++) {
    Inet_pton(AF_INET, hostname_to_ip_address(argv[i], ipaddr_str), &ia);
    tour.nodes[i] = ia;
    tour.num_nodes = i + 1;
  }

  // TODO: Add handlers.
  fdset_add(&fds, &fds.rev,  rt, &rt, on_rt_recv);
  fdset_add(&fds, &fds.exev, rt, &rt, on_rt_error);

  fdset_add(&fds, &fds.rev,  pg, &pg, on_pg_recv);
  fdset_add(&fds, &fds.exev, pg, &pg, on_pg_error);

  fdset_add(&fds, &fds.rev,  pf, &pf, on_pf_recv);
  fdset_add(&fds, &fds.exev, pf, &pf, on_pf_error);

  fdset_add(&fds, &fds.rev,  udp, &udp, on_udp_recv);
  fdset_add(&fds, &fds.exev, udp, &udp, on_udp_error);

  if (argc > 1) {
    // TODO: Start a tour.
    r = areq(tour.nodes[1], &hwaddr);
    assert_ge(r, 0);

    // TODO: Construct and send out the first tour packet.
  }

  timeout.tv_sec =  1; // FIXME when we know better
  timeout.tv_usec = 0;

  r = fdset_poll(&fds, &timeout, on_timeout);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
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
  tour_setup(argc, argv);
  return 0;
}
