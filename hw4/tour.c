// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "unp.h"
#include "fdset.h"
#include "api.h"
#include <linux/if_ether.h>
#include <time.h>

#define IP_HEADER_ID   0x04b6
#define ICMP_HEADER_ID 0x5146

int rt, pg, pf, udp;        // rt -> Routing
                            // pg -> Ping
                            // pf -> PF Packet
                            // udp -> For Multicast
ipaddr_ascii myip_a;        // My (eth0) IP address in presentation format
ipaddr_n     myip_n;        // My (eth0) IP address in network byte order
eth_addr_n   my_hwaddr;     // My (eth0) Hardware Address
char         my_name[30];   // My Host Name
int          my_ifindex;    // if_index for eth0
tour_list tour;             // List of IP addresses (in network
                            // order). Includes my own IP address.
bool visited;               // Whether this node has been touched by a tour
bool last_node_in_tour = 
  FALSE;                    // Is this the last node in the tour?
bool tour_end_msg_sent =
  FALSE;                    // Have we sent the tour ending message, yet?
uint32_t last_visit_time;   // If this is the last node in the tour,
                            // when did we realize this?
uint32_t last_udp_mcast_recv_time;
                            // When was the last time we received a 
                            // multicast message?
bool can_ping = TRUE;       // Can we keep pinging?
bool mcast_received;        // Have I received a multicast request yet?
fdset fds;                  // List of FDs to wait on
vector ping_hosts;          // List of hosts to ping every second
struct sockaddr_in s_addr;  // The multicast address
char msg_buf[500];          // A temporary message buffer
struct ip_mreq mreq;

// Sample PING response:
//
// 64 bytes from vm2 (192.168.1.102): icmp_seq=1 ttl=64 time=14.6 ms

typedef struct ping_info_t {
  ipaddr_n ip;
  int last_ping_ms;
  int num_pings;
  int seq;
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
add_ping_host(ipaddr_n ip, int ntries) {
  int i;
  ping_info_t *ppif;
  ping_info_t pif;
  for (i = 0; i < vector_size(&ping_hosts); ++i) {
    ppif = vector_at(&ping_hosts, i);
    if (ip.s_addr == ppif->ip.s_addr) {
      return;
    }
  }
  pif.ip = ip;
  pif.last_ping_ms = current_time_in_ms() - 5000;
  pif.num_pings = ntries;
  pif.seq = 1;
  vector_push_back(&ping_hosts, &pif);
}

#define PING_PACKET_SIZE 70


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
  
  if (last_node_in_tour) {
    if (!tour_end_msg_sent && 
    (current_time_in_ms() - last_visit_time >= 5000)) {
      tour_end_msg_sent = TRUE;
      
      snprintf(msg_buf, sizeof(msg_buf), "This is node %s. Tour has ended. Group members please identify yourselves.", my_name);
      send_mcast_msg(msg_buf, strlen(msg_buf)); 
    }
  }

  if (!can_ping) {
    if (current_time_in_ms() - last_udp_mcast_recv_time >= 5000) {
      INFO("No Multicast message received for >= 5s. Ending tour.\n%s", "");
      exit(0);
    }
    return;
  }

  // VERBOSE("send_ping_packets. Queue Size: %d\n", vector_size(&ping_hosts));
  picmp = (ip_icmp_hdr_t*)buff;
  ef    = (eth_frame*)buff;
  for (i = 0; i < vector_size(&ping_hosts); ++i) {
    pif = vector_at(&ping_hosts, i);

    if (pif->num_pings == 0) {
      continue;
    }

    if (current_time_in_ms() - pif->last_ping_ms < 3000) {
      continue;
    }

    pif->last_ping_ms = current_time_in_ms();
    pp_ip(pif->ip, ip_str, 20);

    VERBOSE("Actually sending a PING packet to %s\n", ip_str);
    memset(buff, 0, sizeof(buff));
    picmp->iphdr.version  = 4;
    picmp->iphdr.ihl      = 5;
    picmp->iphdr.id       = htons(IP_HEADER_ID);
    picmp->iphdr.tos      = 0;
    picmp->iphdr.tot_len  = htons(PING_PACKET_SIZE - 14);
    picmp->iphdr.frag_off = htons(1 << 14);
    picmp->iphdr.ttl      = 8;
    picmp->iphdr.protocol = 1;
    picmp->iphdr.saddr    = myip_n.s_addr;
    picmp->iphdr.daddr    = pif->ip.s_addr;

    picmp->icmphdr.type   = (unsigned char)(ICMP_ECHO);
    picmp->icmphdr.code   = 0;
    picmp->icmphdr.un.echo.id = htons(ICMP_HEADER_ID);
    picmp->icmphdr.un.echo.sequence = htons(pif->seq++);

    sprintf(picmp->icmpdata, "%d", current_time_in_ms());

    picmp->icmphdr.checksum = 
      icmp_checksum((uint16_t*)&picmp->icmphdr, PING_PACKET_SIZE - 34);

    picmp->iphdr.check    = 
      icmp_checksum((uint16_t*)&picmp->iphdr, PING_PACKET_SIZE - 14);

    r = areq(pif->ip, &hwaddr);
    assert_ge(r, 0);

    memcpy(picmp->dst_eth_addr.addr, hwaddr.sll_addr, 6);

    eth_str = pp_eth(picmp->dst_eth_addr.addr);
    INFO("Eth addr for IP addr %s is %s\n",
         pp_ip(pif->ip, ip_str, 20), eth_str.addr);

    VERBOSE("Size of sent payload is: %d\n", sizeof(eth_frame) - OFFSETOF(ip_icmp_hdr_t, icmpdata));
    picmp->src_eth_addr = my_hwaddr;
    picmp->protocol = htons(ETH_P_IP);
    send_over_ethernet(pf, ef, PING_PACKET_SIZE, my_ifindex, TRUE);
  }
}

void
send_mcast_msg(char *buf, size_t buflen) {
  INFO("Node %s. Sending: %s\n", my_name, buf); 
  Sendto(udp, buf, buflen, 0, (SA *)&s_addr, sizeof(s_addr));
}

void
recv_mcast_msg(char *buf, size_t buflen) {
  size_t addrlen, rc;
  struct sockaddr_in r_addr;
  addrlen = sizeof(r_addr);
  rc = Recvfrom(udp, buf, buflen-1, 0, (SA *)&r_addr, &addrlen);
  if (rc > 0) {
    buf[rc] = '\0';
  }
  INFO("Node %s. Received: %s.\n", my_name, buf);
}

void
on_timeout(void *opaque) {
  // FIXME: Change to VERBOSE
  INFO("Timed out.%s\n", "");

  // Send out ping packets.
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
join_mcast_group(ipaddr_n mcast_addr, uint16_t mcast_port) {
  char buf[100];
  struct sockaddr_in addr;
  memset(&s_addr, 0, sizeof(s_addr));
  s_addr.sin_family = AF_INET;
  s_addr.sin_addr.s_addr = mcast_addr.s_addr;
  s_addr.sin_port = htons(mcast_port);

  visited = TRUE;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(mcast_port);

  Bind(udp, (struct sockaddr *) &addr, sizeof(addr));

  mreq.imr_multiaddr.s_addr = mcast_addr.s_addr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  Setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  INFO("Joined the multicast group at %s : %d\n",
    pp_ip(mcast_addr, buf, sizeof(buf)), mcast_port);
}

void
on_rt_recv(void *opaque) {
  // TODO: Check the index of the route on this packet and ping the
  // sender if we aren't already pinging the sender. Increment pointer
  // and forward or send out multicast packet if we are the last node
  // on the route.
  int r;
  struct sockaddr_in sa;
  socklen_t addrlen = sizeof(sa);
  char buff[1600];
  char ip_str[20];
  struct iphdr *iphdr;
  tour_pkt *tpkt;
  tour_list *ptour;
  ipaddr_n ip;
  time_t t;
  char tstr[100];

  VERBOSE("on_rt_recv()%s\n", "");
  memset(buff, 0, sizeof(buff));
  r = recvfrom(rt, buff, sizeof(buff), 0, (SA*)&sa, &addrlen);
  VERBOSE("on_rt_recv::r == %d\n", r);
  if (r < 0 && errno == EINTR) {
    return;
  }
  if (r < 0) {
    perror("recvfrom");
    exit(1);
  }

  t = time(NULL);
  pp_ip(sa.sin_addr, ip_str, 20);
  strcpy(tstr, ctime(&t));
  tstr[strlen(tstr) - 1] = '\0';
  INFO("<%s> received source routing message from <%s>\n", tstr, ip_str);

  iphdr = (struct iphdr*)buff;
  tpkt  = (tour_pkt*)(iphdr + 1);
  ptour = &tpkt->tour;

  ++tpkt->current_node_idx;
  VERBOSE("# of nodes in tour: %d, Current Index: %d, Crrant IP: %s\n",
          ptour->num_nodes, tpkt->current_node_idx,
          pp_ip(ptour->nodes[tpkt->current_node_idx], ip_str, 20));

  // Add the previous node to the list of nodes to ping.
  add_ping_host(ptour->nodes[tpkt->current_node_idx - 1], 100);
  
  if (!visited) {
    INFO("This is the first time this node has been visited in the tour.\n%s", "");
    join_mcast_group(tpkt->mcast_addr, tpkt->mcast_port);
  }

  if (tpkt->current_node_idx == ptour->num_nodes - 1) {
    INFO("This is the end, my only friend, the end...%s\n", "");
    last_node_in_tour = TRUE;  
    last_visit_time = current_time_in_ms();
  } else {
    ip = ptour->nodes[tpkt->current_node_idx + 1];

    iphdr->check    = 0;
    iphdr->saddr    = myip_n.s_addr;
    iphdr->daddr    = ip.s_addr;

    sa.sin_addr = ip;

    Sendto(rt, buff, r, 0, (SA*)&sa, sizeof(sa));
  }

  send_ping_packets();
}

void
on_pg_recv(void *opaque) {
  // TODO: Ping response. Probably just print it out.
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  char buff[1600];
  ip_icmp_hdr_t *picmp;
  int sent_at_ms;
  char from_hostname[30];
  char from_ip[30];
  // VERBOSE("on_pg_recv()%s\n", "");
  memset(buff, 0, sizeof(buff));
  r = recvfrom(pg, buff, sizeof(buff), 0, (SA*)&sa, &addrlen);
  // VERBOSE("on_pg_recv::r == %d\n", r);
  if (r < 0 && errno == EINTR) {
    return;
  }
  if (r < 0) {
    perror("recvfrom");
    exit(1);
  }
  picmp = (ip_icmp_hdr_t*)(buff - OFFSETOF(ip_icmp_hdr_t, iphdr));

  // Check ID/type & filter out all packets of type other than ICMP Reply.
  if (picmp->icmphdr.un.echo.id != htons(ICMP_HEADER_ID) || ICMP_ECHOREPLY != picmp->icmphdr.type) {
    send_ping_packets();
    return;
  }

  VERBOSE("Size of received payload is: %d, Type: %d\n",
          r - sizeof(struct iphdr) - sizeof(struct icmphdr),
          picmp->icmphdr.type);
  sscanf(picmp->icmpdata, "%d", &sent_at_ms);
  pp_ip(*(struct in_addr*)&picmp->iphdr.saddr, from_ip, sizeof(from_ip));
  ip_address_to_hostname(from_ip, from_hostname);

  INFO("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%d ms\n",
       r - sizeof(struct iphdr) - sizeof(struct icmphdr),
       from_hostname,
       from_ip,
       ntohs(picmp->icmphdr.un.echo.sequence),
       (int)picmp->iphdr.ttl,
       current_time_in_ms() - sent_at_ms);

  send_ping_packets();
}

void
on_pf_recv(void *opaque) {
  // TODO: Send out the ping request using this socket. If this
  // becomes read ready, we just read the data and ignore it.
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  char buff[1600];
  // VERBOSE("on_pf_recv()%s\n", "");
  r = recvfrom(pf, buff, sizeof(buff), 0, (SA*)&sa, &addrlen);
  // send_ping_packets();
}

void
on_udp_recv(void *opaque) {
  VERBOSE("UDP socket is read ready.\n%s", "");
  if (!can_ping) {
    VERBOSE("Disabling ping now\n%s", "");
  }
  last_udp_mcast_recv_time = current_time_in_ms();
  can_ping = FALSE;
  recv_mcast_msg(msg_buf, sizeof(msg_buf));
  if (!mcast_received) {
    VERBOSE("This is the first time I received a Multicast message.\n%s", "");
    mcast_received = TRUE;
    snprintf(msg_buf, sizeof(msg_buf), "Node %s. I am a member of the group.", my_name);
    send_mcast_msg(msg_buf, strlen(msg_buf));
  }
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
  struct sockaddr_in sa;
  char ipaddr_str[200];
  struct timeval timeout;
  struct hwaddr hwaddr;
  char buff[1600];
  tour_pkt *tpkt;
  struct iphdr *iphdr;

  // This node has not been visited yet
  visited = FALSE;
  // This is not the last node in the tour, yet.
  last_node_in_tour = FALSE;
  // We can ping
  // can_ping = TRUE;
  // I haven't received the mcast, yet.
  mcast_received = FALSE;
  
  utils_init();

  // Get my eth0 IP address.
  populate_myip();
  
  // Get my hostname
  ip_address_to_hostname(myip_a.addr, my_name);
  VERBOSE("My hostname is: %s\n", my_name);

  rt = Socket(AF_INET, SOCK_RAW, IPPROTO_HW);
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

  for (i = 1; i < argc; i++) {
    Inet_pton(AF_INET, hostname_to_ip_address(argv[i], ipaddr_str), &ia);
    VERBOSE("Adding IP %s to the tour at index %d\n", ipaddr_str, i);
    tour.nodes[i] = ia;
    tour.num_nodes = i + 1;
  }

  // Add handlers.
  timeout.tv_sec =  1; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

  fdset_add(&fds, &fds.rev,  rt, &rt, on_rt_recv);
  fdset_add(&fds, &fds.exev, rt, &rt, on_rt_error);

  fdset_add(&fds, &fds.rev,  pg, &pg, on_pg_recv);
  fdset_add(&fds, &fds.exev, pg, &pg, on_pg_error);

  // fdset_add(&fds, &fds.rev,  pf, &pf, on_pf_recv);
  fdset_add(&fds, &fds.exev, pf, &pf, on_pf_error);

  fdset_add(&fds, &fds.rev,  udp, &udp, on_udp_recv);
  fdset_add(&fds, &fds.exev, udp, &udp, on_udp_error);

  if (argc > 1) {
    // Start a tour.
    r = areq(tour.nodes[1], &hwaddr);
    assert_ge(r, 0);

    // Construct and send out the first tour packet.
    memset(buff, 0, sizeof(buff));
    iphdr = (struct iphdr*)buff;
    tpkt = (tour_pkt*)(iphdr + 1);
    memcpy(&tpkt->tour, &tour, sizeof(tour));
    tpkt->current_node_idx = 0;
    
    // Add the multicast address and port
    tpkt->mcast_port = MCAST_PORT;
    Inet_pton(AF_INET, MCAST_ADDR, (void *)&tpkt->mcast_addr);
    
    // Join the Multicast group
    join_mcast_group(tpkt->mcast_addr, tpkt->mcast_port);

    // Send out the packet.
    iphdr->version  = 4;
    iphdr->ihl      = 5;
    iphdr->id       = htons(IP_HEADER_ID);
    iphdr->tos      = 0;
    iphdr->tot_len  = htons(sizeof(struct iphdr) + sizeof(tour_pkt));
    iphdr->frag_off = htons(1 << 14);
    iphdr->ttl      = 8;
    iphdr->protocol = IPPROTO_HW;
    iphdr->saddr    = myip_n.s_addr;
    iphdr->daddr    = tour.nodes[1].s_addr;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = tour.nodes[1];

    VERBOSE("Sending out the tour packet with %d hosts\n", tpkt->tour.num_nodes);

    Sendto(rt, buff, sizeof(struct iphdr) + sizeof(tour_pkt),
           0, (SA*)&sa, sizeof(sa));
  }

  r = fdset_poll(&fds, &timeout, on_timeout);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

int
main(int argc, char **argv) {
  assert_eq(OFFSETOF(ip_icmp_hdr_t, src_eth_addr), 6);
  assert_eq(OFFSETOF(ip_icmp_hdr_t, protocol), 12);
  assert_eq(OFFSETOF(ip_icmp_hdr_t, iphdr), 14);

  VERBOSE("&pf: %p, &msg_buf: %p\n", &pf, msg_buf);

  tour_setup(argc, argv);
  return 0;
}
