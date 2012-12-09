// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "unp.h"
#include "fdset.h"
#include "api.h"
#include <linux/if_ether.h>

int rt, pg, pf, udp;      // rt -> Routing
                          // pg -> Ping
                          // pf -> PF Packet
                          // udp -> For Multicast
ipaddr_ascii myip_a;      // My (eth0) IP address in presentation format
ipaddr_n     myip_n;      // My (eth0) IP address in network byte order
eth_addr_n   my_hwaddr;   // My (eth0) Hardware Address
int          my_ifindex;  // if_index for eth0
tour_list tour;           // List of IP addresses (in network
                          // order). Includes my own IP address.
bool visited;             // Whether this node has been touched by a tour
fdset fds;                // List of FDs to wait on
vector ping_hosts;        // List of hosts to ping every second

typedef struct ping_info_t {
  ipaddr_n ip;
  int last_ping_ms;
  int num_pings;
} ping_info_t;

uint16_t
icmp_checksum(uint16_t* buffer, int size) 
{
    unsigned long cksum = 0;
    
    // Sum all the words together, adding the final byte if size is odd
    while (size > 1) {
      cksum += *buffer++;
      size -= sizeof(*buffer);
    }
    if (size) {
      cksum += *(unsigned char*)buffer;
    }

    // Do a little shuffling
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    
    // Return the bitwise complement of the resulting mishmash
    return (uint16_t)(~cksum);
}

void
send_ping_packets(void) {
  int i, r;
  char buff[1600];
  char ip_str[20];
  eth_addr_ascii eth_str;
  ip_icmp_hdr_t *picmp;
  ping_info_t *pif;
  eth_frame *ef;
  struct hwaddr hwaddr;

  VERBOSE("send_ping_packets. Queue Size: %d\n", vector_size(&ping_hosts));
  picmp = (ip_icmp_hdr_t*)buff;
  ef    = (eth_frame*)buff;
  for (i = 0; i < vector_size(&ping_hosts); ++i) {
    pif = vector_at(&ping_hosts, i);

    if (pif->num_pings == 0) {
      continue;
    }

    if (current_time_in_ms() - pif->last_ping_ms < 1000) {
      continue;
    }

    VERBOSE("Actually sending a packet%s\n", "");
    memset(buff, 0, sizeof(buff));
    picmp->iphdr.version  = 4; // 2;
    picmp->iphdr.ihl      = 5; // 10;
    picmp->iphdr.id       = htons(0x04b6);
    picmp->iphdr.tos      = 0;
    picmp->iphdr.tot_len  = htons(sizeof(eth_frame) - OFFSETOF(ip_icmp_hdr_t, iphdr));
    picmp->iphdr.frag_off = htons(1 << 14);
    picmp->iphdr.ttl      = 8;
    picmp->iphdr.protocol = 1;
    picmp->iphdr.saddr    = myip_n.s_addr;
    picmp->iphdr.daddr    = pif->ip.s_addr;

    picmp->icmphdr.type   = (unsigned char)(ICMP_ECHO);
    picmp->icmphdr.code   = 0;
    picmp->icmphdr.un.echo.id = htons(0x5146);
    picmp->icmphdr.un.echo.sequence = htons(7);

    strcpy(picmp->icmpdata, "Hello world");

    picmp->icmphdr.checksum = 
      icmp_checksum((uint16_t*)&picmp->icmphdr,
                    sizeof(eth_frame) - OFFSETOF(ip_icmp_hdr_t, icmphdr));

    picmp->iphdr.check    = 
      icmp_checksum((uint16_t*)&picmp->iphdr,
                    sizeof(eth_frame) - OFFSETOF(ip_icmp_hdr_t, iphdr));

    r = areq(pif->ip, &hwaddr);
    assert_ge(r, 0);

    memcpy(picmp->dst_eth_addr.addr, hwaddr.sll_addr, 6);

    eth_str = pp_eth(picmp->dst_eth_addr.addr);
    INFO("Eth addr for IP addr %s is %s\n",
         pp_ip(pif->ip, ip_str, 20), eth_str.addr);

    VERBOSE("Size of sent payload is: %d\n", sizeof(eth_frame) - OFFSETOF(ip_icmp_hdr_t, icmpdata));
    picmp->src_eth_addr = my_hwaddr;
    picmp->protocol = htons(ETH_P_IP);
    send_over_ethernet(pf, ef, my_ifindex);
  }
}

void
on_timeout(void *opaque) {
  // FIXME: Change to VERBOSE
  INFO("Timed out.%s\n", "");

  // TODO: Send out ping packets.
  send_ping_packets();
}

void
populate_myip(void) {
  struct hwa_info *head, *h;
  struct sockaddr *sa;
  bool found = FALSE;
  eth_addr_ascii eth_str;

  head = Get_hw_addrs();
  for (h = head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0")) {
      sa = (SA *)h->ip_addr;
      strcpy(myip_a.addr, (char *)Sock_ntop_host(sa, sizeof(*sa)));      
      myip_n     = ((struct sockaddr_in *)sa)->sin_addr;
      memcpy(my_hwaddr.addr, h->if_haddr, sizeof(h->if_haddr));
      my_ifindex = h->if_index;

      eth_str = pp_eth(my_hwaddr.addr);
      INFO("My (IP:ETH:IDX): (%s:%s:%d)\n", myip_a.addr,
           eth_str.addr, my_ifindex);
      found = TRUE;
      break;
    }
  }
  assert(found);
}

void
on_rt_recv(void *opaque) {
  // TODO: Check the index of the route on this packet and ping the
  // sender if we aren't already pinging the sender. Increment pointer
  // and forward or send out multicast packet if we are the last node
  // on the route.
}

void
on_pg_recv(void *opaque) {
  // TODO: Ping response. Probably just print it out.
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  char buff[1600];
  ip_icmp_hdr_t *picmp;
  VERBOSE("on_pg_recv()%s\n", "");
  memset(buff, 0, sizeof(buff));
  r = recvfrom(pg, buff, sizeof(buff), 0, (SA*)&sa, &addrlen);
  VERBOSE("on_pg_recv::r == %d\n", r);
  if (r < 0 && errno == EINTR) {
    return;
  }
  if (r < 0) {
    perror("recvfrom");
    exit(1);
  }
  picmp = (ip_icmp_hdr_t*)(buff - OFFSETOF(ip_icmp_hdr_t, iphdr));
  VERBOSE("Size of received payload is: %d\n", r - sizeof(*picmp) + 14);
  INFO("Ping response: %s\n", picmp->icmpdata);
}

void
on_pf_recv(void *opaque) {
  // TODO: Send out the ping request using this socket. If this
  // becomes read ready, we just read the data and ignore it.
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  char buff[1600];
  VERBOSE("on_pf_recv()%s\n", "");
  r = recvfrom(pf, buff, sizeof(buff), 0, (SA*)&sa, &addrlen);

}

void
on_udp_recv(void *opaque) {
  // TODO: Received the multicast packet.
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
  ping_info_t pif;

  utils_init();

  // Get my eth0 IP address.
  populate_myip();

  rt = Socket(AF_INET, SOCK_RAW, htons(IPPROTO_HW));
  // IP_HDRINCL means that the sender MUST include the header while
  // sending out the packet.
  Setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));

  pg = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  pf = Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  udp = Socket(AF_INET, SOCK_DGRAM, 0); // FIXME Fix the protocol

  VERBOSE("rt: %d, pg: %d, pf: %d, udp: %d\n", rt, pg, pf, udp);

  vector_init(&ping_hosts, sizeof(ping_info_t));

  Inet_pton(AF_INET, hostname_to_ip_address(myip_a.addr, ipaddr_str), &ia);
  VERBOSE("Tour starts at IP: %s\n", ipaddr_str);
  tour.nodes[0] = ia;
  tour.num_nodes = 1;

  // <hack>
  pif.ip = ia;
  pif.last_ping_ms = current_time_in_ms() - 3000;
  pif.num_pings = 100;
  // vector_push_back(&ping_hosts, &pif);
  // </hack>

  for (i = 1; i < argc; i++) {
    Inet_pton(AF_INET, hostname_to_ip_address(argv[i], ipaddr_str), &ia);
    VERBOSE("Adding IP %s to the tour at index %d\n", ipaddr_str, i);
    tour.nodes[i] = ia;
    tour.num_nodes = i + 1;

    // <hack>
    pif.ip = ia;
    pif.last_ping_ms = current_time_in_ms() - 3000;
    pif.num_pings = 100;
    vector_push_back(&ping_hosts, &pif);
    // </hack>

  }

  // Add handlers.
  timeout.tv_sec =  1; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

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
  assert_eq(OFFSETOF(ip_icmp_hdr_t, src_eth_addr), 6);
  assert_eq(OFFSETOF(ip_icmp_hdr_t, protocol), 12);
  assert_eq(OFFSETOF(ip_icmp_hdr_t, iphdr), 14);

  tour_setup(argc, argv);
  return 0;
}
