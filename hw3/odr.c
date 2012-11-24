// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "odr.h"
#include "treap.h"
#include "fdset.h"
#include "myassert.h"
#include "gitcommit.h"
#include <unistd.h>
#include <signal.h>

serv_dsock s;             // Domain socket to listen on & serve requests
vector cli_table;         // Table containing entries of all clients. vector<cli_entry>
vector route_table;       // The Routing Table. vector<route_entry>
uint32_t next_e_portno;   // Next Ephemeral Port Number to assign
char my_ipaddr[16];       // My IP Address
int pf_sockfd = -1;       // Sockfd corresponding to the PF_PACKET socket
uint32_t staleness;       // Staleness paramenter
fdset fds;                // fdset for the client's domain socket
vector odr_send_q;        // A queue of outgoing packets to send to the other ODR. vector<odr_pkt*>
struct hwa_info *h_head;  // The hardware interfaces
treap iface_treap;        // Interface Index to Interface Mapping. treap<int, struct hwa_info*>
treap cli_port_map;       // Mapping from port # to cli_entry. treap<int, cli_entry*>
int broadcast_id = 1;     // The global broadcast ID we use for RREQ and RREP packets
vector bid_table;         // The ID containing the mapping of IP to Broadcast ID
const char *appname = 0;  // The value of argv[0]

void
sigsegv_handler(int sig) {
  signal (SIGSEGV, SIG_DFL);
  printf("**Segmentation Fault detected\n");
  fflush(stdout);
  raise (SIGSEGV);
}

void
sigint_handler(int sig) {
  signal (SIGINT, SIG_DFL);
  printf("**SIGINT detected\n");
  fflush(stdout);
  raise (SIGINT);
}

void
sigterm_handler(int sig) {
  signal (SIGTERM, SIG_DFL);
  printf("**SIGTERM detected\n");
  fflush(stdout);
  raise (SIGTERM);
}

/* Print out the routing table */
void
print_routing_table(void) {
  int i;
  route_entry *e;
  char buff[20];
  printf("Routing Table:\n");
  for (i = 0; i < vector_size(&route_table); ++i) {
    e = (route_entry*)vector_at(&route_table, i);
    pretty_print_eth_addr(e->next_hop, buff);
    printf("Route: %s to %s via %s with %d hops\n", my_ipaddr, e->ip_addr, buff, e->nhops_to_dest);
  }
  fflush(stdout);
}

/* Add an entry to the cli_table, which holds a list of cli_entry's
 * for every client that has contacted us.
 */
cli_entry *
add_cli_entry(struct sockaddr_un *cliaddr) {
  cli_entry *e;
  struct sockaddr_un *caddr = MALLOC(struct sockaddr_un);
  memcpy(caddr, cliaddr, sizeof(*cliaddr));

  e = MALLOC(cli_entry);
  e->last_id = 0;
  e->cliaddr = caddr;
  e->e_portno = next_e_portno++;

  vector_push_back(&cli_table, (void *)e);
  treap_insert(&cli_port_map, e->e_portno, e);

  VERBOSE("Added an entry for client with sun_path: %s and port number: %d\n", cliaddr->sun_path, e->e_portno);
  return e;
}

/* Fetch a cli_entry from the cli_table given a 'struct sockaddr_un'
 * for that client address. *Always* returns non-NULL.
 */
cli_entry *
get_cli_entry(struct sockaddr_un *cliaddr) {
  int i;
  cli_entry *e, *t;
  e = NULL;
  for (i = 0; i < vector_size(&cli_table); i++) {
    t = (cli_entry *) vector_at(&cli_table, i);
    if (!strcmp(t->cliaddr->sun_path, cliaddr->sun_path)) {
      e = t;
      break;
    }
  }
  if (!e) {
    // Add an entry for this client
    e = add_cli_entry(cliaddr);
  }
  return e;
}

BOOL
is_stale_entry(route_entry *e) {
  if (current_time_in_ms() - (e->last_updated_at_ms) >= staleness) {
    return TRUE;
  }
  return FALSE;
}

/* Fetch the route_entry which will help us route the odr_pkt 'p' to
 * its destination. Returns NULL if no such route is found.
 */
route_entry *
get_route_entry(const char *ip) {
  int i;
  route_entry *r = NULL;
  for (i = 0; i < vector_size(&route_table); i++) {
    r = vector_at(&route_table, i);
    if (!strcmp(r->ip_addr, ip)) {
      // We have a match
      return r;
    }
  }
  return NULL;
}

void
prune_routing_table(const char *ip, int flags) {
  int i;
  route_entry *r = NULL;
  vector alive;
  vector_init(&alive, sizeof(route_entry));

  for (i = 0; i < vector_size(&route_table); i++) {
    r = vector_at(&route_table, i);
    ASSERT(strcmp(my_ipaddr, r->ip_addr));
    if (is_stale_entry(r) ||
        (!strcmp(r->ip_addr, ip) && (flags & ROUTE_REDISCOVERY_FLG))) {
      // This is a stale entry
    } else {
      vector_push_back(&alive, r);
    }
  }
  vector_swap(&route_table, &alive);
  vector_destroy(&alive);
}

/* We also need to time out older clients that don't exist. We can do
 * this by checking if the socket file for that client exists or not.
 *
 */
void
prune_cli_table(void) {
  int i;
  cli_entry *c = NULL;
  vector alive;
  vector_init(&alive, sizeof(cli_entry));

  for (i = 0; i < vector_size(&cli_table); i++) {
    c = vector_at(&cli_table, i);
    // No error accessing the file, or the file is
    // the time server's file
    if (access(c->cliaddr->sun_path, R_OK) == 0 || 
        !strcmp(c->cliaddr->sun_path, SRV_DGPATH)) {
      // No error accessing the file
      vector_push_back(&alive, c);
    } else {
      treap_delete(&cli_port_map, c->e_portno);
      // Zero out structures to help debugging.
      memset(c->cliaddr, 0, sizeof(*(c->cliaddr)));
      free(c->cliaddr);
      memset(c, 0, sizeof(*c));
      free(c);
    }
  }
  vector_swap(&cli_table, &alive);
  vector_destroy(&alive);
}

void
odr_packet_print(odr_pkt *pkt) {
  INFO("ODR Packet { Type: %s, bcast_id: %d, hop_count: %d, src: %s:%d, "
       "dst: %s:%d, size: %d }\n",
       pkt_type_to_str(pkt->type), pkt->broadcast_id, pkt->hop_count,
       pkt->src_ip, pkt->src_port,
       pkt->dst_ip, pkt->dst_port, pkt->msg_size);
}

void
odr_setup(void) {
  struct hwa_info *h;
  struct sockaddr *sa;
  struct sockaddr_un *serv_addr;
  int r, i;
  unsigned int seed;
  char *cptr;
  char buff[20];
  FILE *pf;
  vector hwaddrs;

  vector_init(&cli_table,   sizeof(cli_entry));
  vector_init(&route_table, sizeof(route_entry));
  vector_init(&bid_table, sizeof(bid_entry));
  treap_init(&iface_treap);
  treap_init(&cli_port_map);
  vector_init(&odr_send_q,  sizeof(odr_pkt*));
  next_e_portno = TIME_SERVER_PORT;

  pf = fopen("/dev/urandom", "r");
  assert(pf);
  r = fread(&seed, sizeof(seed), 1, pf);
  assert(r == 1);
  srand(seed);
  fclose(pf);
  pf = NULL;

  // broadcast_id = rand() % 10000;

  h_head = Get_hw_addrs();
  vector_init(&hwaddrs, sizeof(char*));

  for (h = h_head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0") && h->ip_addr != NULL) {
      sa = h->ip_addr;
      strcpy(my_ipaddr, (char *)Sock_ntop_host(sa, sizeof(*sa)));
      INFO("My IP Address: %s\n", my_ipaddr);
    }
    
    if (strcmp(h->if_name, "lo") && strncmp(h->if_name, "eth0", 4)) {
      INFO("Discovered interface[%d]: %s\n", h->if_index, h->if_name);
      cptr = h->if_haddr;
      vector_push_back(&hwaddrs, &cptr);
      treap_insert(&iface_treap, h->if_index, h);
    }
  }

  for (i = 0; i < vector_size(&hwaddrs); ++i) {
    pretty_print_eth_addr(*(char**)vector_at(&hwaddrs, i), buff);
    printf("Topology: %s %s\n", my_ipaddr, buff);
  }

  // Create the PF_PACKET socket
  pf_sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ODR_PROTOCOL));
  VERBOSE("Sucessfully created the PF_PACKET socket\n%s", "");
  serv_addr = MALLOC(struct sockaddr_un);
  r = mkdir("/tmp/dynamic_duo/", 0755);
  strcpy(serv_addr->sun_path, SRV_DGPATH);
  serv_addr->sun_family = AF_LOCAL;
  add_cli_entry(serv_addr);
  create_odr_dsock(&s);
}

void
send_over_ethernet(eth_addr_t from, eth_addr_t to, void *data,
                   int len, int iface_idx) {
  eth_frame ef;
  char src_addr[20], dst_addr[20];

  pretty_print_eth_addr(from.eth_addr, src_addr);
  pretty_print_eth_addr(to.eth_addr, dst_addr);

  memset(&ef, 0, sizeof(ef));
  // memset(&ef.preamble, 0xaa, sizeof(ef.preamble));
  // ef.delimiter = 0xab;
  ef.dst_eth_addr = hton6(to);
  ef.src_eth_addr = hton6(from);
  ef.protocol = htons(ODR_PROTOCOL);

  VERBOSE("Sending an eth_frame (%s -> %s) of size: %d. Payload size: %d\n",
          src_addr, dst_addr, sizeof(eth_frame), len);

  // Copy the payload
  memcpy(ef.payload, data, len);
  send_eth_pkt(&ef, iface_idx);
}

/* Start the process of route discovery. This function floods all the
 * interfaces with a PKT_RREQ packet with the destination address set
 * as 0xff:ff:ff:ff:ff:ff.
 *
 */
void
odr_start_route_discovery(odr_pkt *pkt, int except_ifindex, BOOL send_as_me) {
  // We need to send a PKT_RREQ type ODR packet, wrapped
  // in an ethernet frame

  // Make a new ODR Packet
  odr_pkt rreq_pkt;
  eth_addr_t src_addr, dst_addr;
  struct hwa_info *h;
  int odr_pkt_hdr_sz;

  rreq_pkt = *pkt;
  rreq_pkt.type = PKT_RREQ;
  if (send_as_me) {
    rreq_pkt.broadcast_id = broadcast_id++;
    strcpy(rreq_pkt.src_ip, my_ipaddr);
    VERBOSE("Sending a packet originally sent by %s, as me (%s)\n",
            pkt->src_ip, rreq_pkt.src_ip);
  } else {
    rreq_pkt.broadcast_id = pkt->broadcast_id;
  }

  // Zero out the data.
  memset(rreq_pkt.msg, 0,   sizeof(rreq_pkt.msg));
  memset(dst_addr.eth_addr, 0xff, sizeof(dst_addr));
  odr_pkt_hdr_sz = (int)(((odr_pkt*)(0))->msg);

  VERBOSE("odr_start_route_discovery::Flooding the network with a PKT_RREQ [broadcast_id: %d] for destination IP: %s\n", rreq_pkt.broadcast_id, rreq_pkt.dst_ip);
  for (h = h_head; h != NULL; h = h->hwa_next) {
    // We don't send the message on eth0 and its aliases, and lo
    if (!strncmp(h->if_name, "eth0", 4) || !strcmp(h->if_name, "lo")) {
      continue;
    }

    // If we don't want to flood on a particular index, we will use this
    if (except_ifindex == h->if_index) {
      continue;
    }

    ASSERT(strcmp(rreq_pkt.src_ip, rreq_pkt.dst_ip));
    memcpy(src_addr.eth_addr, h->if_haddr, sizeof(h->if_haddr));
    send_over_ethernet(src_addr, dst_addr, &rreq_pkt,
                       odr_pkt_hdr_sz, h->if_index);
  }
}

void
update_bid_entry(odr_pkt *pkt) {
  int i;
  BOOL seen;
  bid_entry *b;
  seen = FALSE;
  for (i = 0; i < vector_size(&bid_table); i++) {
    b = vector_at(&bid_table, i);
    if (!strcmp(pkt->src_ip, b->src_ip)) {
      b->bid = pkt->broadcast_id;
      seen = TRUE;
      break;
    }
  }
  if (seen == FALSE) {
    b = MALLOC(bid_entry);
    strcpy(b->src_ip, pkt->src_ip);
    b->bid = pkt->broadcast_id;
    vector_push_back(&bid_table, b);
  }
}

BOOL
seen_packet_before(odr_pkt *pkt) {
  int i;
  BOOL seen;
  bid_entry *b;
  seen = FALSE;
  for (i = 0; i < vector_size(&bid_table); i++) {
    b = vector_at(&bid_table, i);
    if (!strcmp(pkt->src_ip, b->src_ip) && (b->bid >= pkt->broadcast_id)) {
      seen = TRUE;
      break;
    }
  }
  if (seen == FALSE) {
    update_bid_entry(pkt);
  }
  return seen;
}

BOOL
should_process_packet(odr_pkt *pkt) {
  if (pkt->type == PKT_RREQ && seen_packet_before(pkt)) {
    INFO("Dropping previously seen PKT_RREQ from %s:%d -> %s:%d with broadcast_id: %d\n",
         pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->broadcast_id);
    // Caller free(3)s packet if necessary.
    return FALSE;
  }

  ++pkt->hop_count;
  if (pkt->hop_count >= MAX_HOP_COUNT) {
    INFO("Dropping packet from %s:%d -> %s:%d because hop count reached %d\n",
         pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->hop_count);
    // Caller free(3)s packet if necessary.
    return FALSE;
  }
  return TRUE;
}

void
send_eth_pkt(eth_frame *ef, int iface_idx) {
  struct sockaddr_ll sa;
  int i;
  unsigned char mask = 0xff;

  VERBOSE("send_eth_pkt(iface_idx: %d)\n", iface_idx);

  memset(&sa, 0, sizeof(sa));
  sa.sll_family   = PF_PACKET;
  sa.sll_hatype   = ARPHRD_ETHER;
  sa.sll_pkttype  = PACKET_BROADCAST;
  sa.sll_protocol = ef->protocol;
  sa.sll_ifindex  = iface_idx;
  sa.sll_halen    = 6;

  for (i = 0; i < 6; ++i) {
    mask &= *(unsigned char*)(ef->dst_eth_addr.eth_addr + i);
  }

  if (mask != 0xff) {
    sa.sll_pkttype = PACKET_OTHERHOST;
  }

  memcpy(sa.sll_addr, ef->dst_eth_addr.eth_addr, 6);
  Sendto(pf_sockfd, (void *)ef, sizeof(eth_frame), 0, (SA *)&sa, sizeof(sa));
  VERBOSE("send_eth_pkt() terminated successfully\n%s", "");
}

/* Update the routing table based on the type of the packet and the
 * source & destination addresses.
 */
void
update_routing_table(odr_pkt *pkt, struct sockaddr_ll *from) {
  route_entry *e;
  char via_eth_addr[20], via_eth_addr_old[20];

  pretty_print_eth_addr((char*)from->sll_addr, via_eth_addr);

  VERBOSE("update_routing_table::(%s -> %s); hop_count: %d; via: %s\n",
          pkt->src_ip, pkt->dst_ip, pkt->hop_count, via_eth_addr);

  if (pkt->type != PKT_RREQ && pkt->type != PKT_RREP) {
    // Ignore this packet since it is neither an RREQ nor is it an
    // RREP.
    VERBOSE("Ignoring packet since it is of type: %d\n", pkt->type);
    return;
  }

  if (is_my_ip(pkt->src_ip)) {
    VERBOSE("Ignoring packet since the source IP %s is mine\n", pkt->src_ip);
    return;
  }

  // We got a request packet from someone. Update the reverse path
  // to that host as via the host we got this packet from.
  e = get_route_entry(pkt->dst_ip);
  if (!e) {
    INFO("New routing table entry to %s via %s\n", pkt->src_ip, via_eth_addr);
    // We have a new routing table entry.
    e = MALLOC(route_entry);
    strcpy(e->ip_addr, pkt->src_ip);
    memcpy(e->next_hop, from->sll_addr, sizeof(e->next_hop));
    e->iface_idx          = from->sll_ifindex;
    e->nhops_to_dest      = pkt->hop_count;
    e->last_updated_at_ms = current_time_in_ms();
    vector_push_back(&route_table, e);
    free(e);
  } else {
    if (e->nhops_to_dest > pkt->hop_count) {
      pretty_print_eth_addr(e->next_hop, via_eth_addr_old);
      INFO("Replacing older routing table entry to (%s via %s with "
           "hop count %d) with (%s via %s with hop count %d)\n",
           e->ip_addr, via_eth_addr_old, e->nhops_to_dest,
           pkt->src_ip, via_eth_addr, pkt->hop_count);

      // Replace the older entry.
      strcpy(e->ip_addr, pkt->src_ip);
      memcpy(e->next_hop, from->sll_addr, sizeof(e->next_hop));
      e->iface_idx          = from->sll_ifindex;
      e->nhops_to_dest      = pkt->hop_count;
      e->last_updated_at_ms = current_time_in_ms();
    }
  }
}

void
act_on_packet(odr_pkt *pkt, struct sockaddr_ll *from) {
  route_entry *e;
  char via_eth_addr[20];
  BOOL am_i_the_destination = FALSE;
  BOOL rrep_sent = FALSE;

  pretty_print_eth_addr((char*)from->sll_addr, via_eth_addr);

  VERBOSE("act_on_packet::(%s -> %s); type: %s; hop_count: %d; via: %s\n",
          pkt->src_ip, pkt->dst_ip, 
          pkt_type_to_str(pkt->type),
          pkt->hop_count, via_eth_addr);

  if (pkt->type != PKT_RREQ && pkt->type != PKT_RREP) {
    // Ignore this packet since it is neither an RREQ nor is it an
    // RREP.
    VERBOSE("Ignoring packet since it is of type: %d\n", pkt->type);
    return;
  }

  if (pkt->type == PKT_RREQ) {
    // If this packet's destination IP is our IP OR we have an
    // un-expired route to the destination, we reply with a
    // PKT_RREP. But this is only if the RREP was not sent 
    if (!(pkt->flags & RREP_ALREADY_SENT_FLG)) {
      e = get_route_entry(pkt->dst_ip);
      am_i_the_destination = is_my_ip(pkt->dst_ip);
      if (am_i_the_destination || e) {
        VERBOSE("The miracle, RREQ -> RREP conversion.%s\n", "");
        if (am_i_the_destination) {
          rrep_sent = odr_queue_or_send_rrep(pkt->dst_ip, pkt->src_ip, 0);
        } else {
          rrep_sent = odr_queue_or_send_rrep(pkt->dst_ip, pkt->src_ip, e->nhops_to_dest);
        }
        // odr_send_rrep(pkt->dst_ip, pkt->src_ip, e, from);
        if (rrep_sent) {
          pkt->flags |= RREP_ALREADY_SENT_FLG;
        }

      } // if (am_i_the_destination || e) {

    } // if (!(pkt->flags & RREP_ALREADY_SENT_FLG))

    // Send an RREQ in every case.
    odr_start_route_discovery(pkt, from->sll_ifindex, FALSE);

  } else if (pkt->type == PKT_RREP) {
    // PKT_RREP (FIXME)
    //
    // Propagate this RREP packet to the next hop on the path to the
    // destination if a path to the destination is available. If such
    // a path isn't available, we flood the interfaces of this machine
    // with an RREQ to try and discover a path to the destination.
    VERBOSE("Received an RREP for dst_ip: %s, from src_ip: %s\n", pkt->dst_ip, pkt->src_ip);
    // TODO
    // Doesn't just odr_queue_or_send_rrep suffice?
    e = get_route_entry(pkt->dst_ip);
    if (e) {
      // odr_send_rrep(pkt->src_ip, pkt->dst_ip, e, from);
      odr_queue_or_send_rrep(pkt->src_ip, pkt->dst_ip, e->nhops_to_dest + 1);
    } else {
      // TODO: Find out if we should not flood the interface on which
      // the RREP arrived.
      //
      // Q. Menghani, why is this FALSE?
      //
      odr_start_route_discovery(pkt, -1, TRUE);
    }
  } else if (pkt->type == PKT_DATA) {
    VERBOSE("Received a PKT_DATA packet for dst_ip: %s, from src_ip: %s\n", pkt->dst_ip, pkt->src_ip);
    e = get_route_entry(pkt->dst_ip);
    if (e) {
      VERBOSE("Have a route to send the PKT_DATA packet\n%s", "");
    } else {
      VERBOSE("Don't have a route to send the PKT_DATA packet. Queuing it.\n%s", "");
    }
    odr_route_message(pkt, e);
  }
}

/* Send the RREP to 'toip' if a path to the source (fromip) is
 * avaibale or enqueue it for sending later in the odr_send_q.
 * 
 * Returns
 *  TRUE  if the RREP was sent
 *  FALSE if the RREP was queued
 */
BOOL
odr_queue_or_send_rrep(const char *fromip, const char *toip,
                       int hop_count) {
  odr_pkt *rrep_pkt;
  route_entry *r;
  struct hwa_info *h;
  eth_addr_t next_hop_addr;
  eth_addr_t iface_addr;
  char eth_buf[20];
  BOOL ret;
  int i;
  odr_pkt *pkt;

  VERBOSE("odr_queue_or_send_rrep(%s -> %s [%d] hops)\n", fromip, toip, hop_count);

  rrep_pkt = MALLOC(odr_pkt);
  memset(rrep_pkt, 0, sizeof(rrep_pkt));
  rrep_pkt->type          = PKT_RREP;
  rrep_pkt->hop_count     = hop_count;
  // TODO Pass the port numbers
  // rrep_pkt->src_port      = ?
  // rrep_pkt->dst_port      = ?
  strcpy(rrep_pkt->src_ip, fromip);
  strcpy(rrep_pkt->dst_ip, toip);
  
  r = get_route_entry(toip);
  if (r == NULL) {
    // Did not find a route entry to send this RREP
    // Queue this    
    VERBOSE("Could not find a route to IP: %s, queueing this RREP\n", toip);
    
    ASSERT(rrep_pkt->type == PKT_RREQ || rrep_pkt->type == PKT_RREP || rrep_pkt->type == PKT_DATA);
    vector_push_back(&odr_send_q, &rrep_pkt); 
    VERBOSE("odr_send_q size: %d\n", vector_size(&odr_send_q));
    for (i = 0; i < vector_size(&odr_send_q); i++) {
      pkt = *(odr_pkt**)vector_at(&odr_send_q, i);
      ASSERT(pkt->type == PKT_RREQ || pkt->type == PKT_RREP || pkt->type == PKT_DATA);
    }
    ret = FALSE;
  } else {
    h = (struct hwa_info *)treap_get_value(&iface_treap, r->iface_idx);
    memcpy(next_hop_addr.eth_addr, r->next_hop, sizeof(r->next_hop));
    memcpy(iface_addr.eth_addr, h->if_haddr, sizeof(h->if_haddr));
    
    pretty_print_eth_addr(next_hop_addr.eth_addr, eth_buf);
    VERBOSE("Found a route to IP: %s, sending this RREP via iface_idx: %d to next_hop_addr: %s\n", toip, r->iface_idx, eth_buf);
    send_over_ethernet(iface_addr, next_hop_addr, (void *)rrep_pkt,
                       sizeof(*rrep_pkt), h->if_index);
    free(rrep_pkt);
    ret = TRUE;
  }
  return ret;
}

/* Route the message 'pkt' to the appropriate recipient by computing
 * the next hop on the route. Also increment the hop_count. If the hop
 * count reaches MAX_HOP_COUNT, we silently drop this packet and print
 * out an INFO statement.
 *
 */
void
odr_route_message(odr_pkt *pkt, route_entry *r) {
  // TODO Where are we handling RREQs and RREPs
  odr_pkt *p;
  struct hwa_info *h;
  eth_addr_t src_addr, dst_addr;

  ASSERT(pkt->type == PKT_RREQ || pkt->type == PKT_RREP || pkt->type == PKT_DATA);

  if (!r) {
    // Look up the routing table, to see if there is an entry
    r = get_route_entry(pkt->dst_ip);
    if (r == NULL) {
      INFO("Could not find a route for IP Address: %s\n", pkt->dst_ip);
      p = MALLOC(odr_pkt);
      memcpy(p, pkt, sizeof(odr_pkt));

      ASSERT(p->type == PKT_RREQ || p->type == PKT_RREP || p->type == PKT_DATA);
      // Queue up the packet to be sent later.
      vector_push_back(&odr_send_q, &p);
      
      // Flush out the queue if you can, and the RREQ is sent if 
      // required
      maybe_flush_queued_data_packets();
      return;
    }
  }

  h = (struct hwa_info *)treap_get_value(&iface_treap, r->iface_idx);
  ASSERT(h);

  INFO("Packet to IP: %s can be routed via interface[%d]: %s\n", pkt->dst_ip, r->iface_idx, h->if_name);

  memcpy(src_addr.eth_addr, h->if_haddr, sizeof(h->if_haddr));
  memcpy(dst_addr.eth_addr, r->next_hop, sizeof(r->next_hop));

  ASSERT(pkt->type == PKT_RREQ || pkt->type == PKT_RREP || pkt->type == PKT_DATA);
  send_over_ethernet(src_addr, dst_addr, pkt, sizeof(*pkt), h->if_index);
  // Don't free(3) the packet here, since the caller will free it.
}

/* Is this ODR packet meant for some client on this machine?
 */
BOOL
is_my_ip(const char *ip) {
  VERBOSE("is_my_ip(other: %s, mine: %s)\n", ip, my_ipaddr);
  return strcmp(ip, my_ipaddr) == 0;
}

/* Deliver the message 'pkt' received by the ODR to the client to
 * which it is destined. In case the client was not found, we silently
 * drop the message and print an INFO message.
 *
 */
void
odr_deliver_message_to_client(odr_pkt *pkt) {
  cli_entry *ce;
  struct sockaddr_un *cliaddr;
  api_msg resp;
  socklen_t clilen;
  int r;
  VERBOSE("odr_deliver_message_to_client:: (%s:%d) -> (%s:%d)\n",
          pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
  ce = (cli_entry*)treap_get_value(&cli_port_map, pkt->dst_port);
  if (!ce) {
    INFO("No client listening on localhost:%d\n", pkt->dst_port);
    return;
  }

  cliaddr = ce->cliaddr;
  VERBOSE("odr_deliver_message_to_client::sun_path: %s\n", cliaddr->sun_path);

  INFO("Delivering message to client at sun_path: %s\n", cliaddr->sun_path);
  memset(&resp, 0, sizeof(resp));
  clilen = sizeof(*cliaddr);
  resp.rtype = MSG_RESPONSE;
  resp.port = pkt->src_port;
  strcpy(resp.ip, pkt->src_ip);
  resp.msg_flag = 0;

  assert_le(API_MSG_SZ, sizeof(resp.msg));
  assert_le(API_MSG_SZ, sizeof(pkt->msg));

  memcpy(resp.msg, pkt->msg, API_MSG_SZ);

  r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) cliaddr, clilen);
  while (r < 0 && errno == EINTR) {
    r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) cliaddr, clilen);
  }

  if (errno == ENOENT) {
    INFO("Could not find client with sun_path: %s\n", cliaddr->sun_path);
    return;
  }

  if (r < 0) {
    perror("sendto");
  }
  assert_eq(r, sizeof(api_msg));
}

odr_pkt *
create_odr_pkt(api_msg *m, cli_entry *c) {
  odr_pkt *o;
  o = MALLOC(odr_pkt);
  o->type = PKT_DATA;
  // FIXME
  // What do we put here? 
  // Is the broadcast_id a number which increases everytime we
  // get a send request? Or is it a client specific count?
  //
  // The broadcast_id is useful only in case of an RREQ packet.
  o->broadcast_id = 0;
  o->hop_count = 0;
  if (m->rtype == MSG_SEND) {
    strcpy(o->src_ip, my_ipaddr);
    strcpy(o->dst_ip, m->ip);
    o->src_port = c->e_portno;
    o->dst_port = m->port;
  }
  o->flags = m->msg_flag;
  strcpy(o->msg, m->msg);

  VERBOSE("create_odr_pkt()%s\n", "");
  odr_packet_print(o);

  return o;
}

void
process_dsock_requests(api_msg *m, cli_entry *c) {
  odr_pkt *pkt;
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m->rtype, c->cliaddr->sun_path);

  if (m->rtype == MSG_CONNECT) {
    // Add entry to cli_table. However, we don't need to since
    // get_cli_entry() already did that for us. Yes, the API is a bit
    // weird that way. In general, no get_*() function should add
    // anything to the table since it is totally counter-intuitive.
  } else if (m->rtype == MSG_SEND) {
    pkt = create_odr_pkt(m, c);
    if (is_my_ip(pkt->dst_ip)) {
      odr_deliver_message_to_client(pkt);
    } else {
      odr_route_message(pkt, NULL);
    }
    free(pkt);
  }
}

/*
 * Helper method to return the pkt_type as a string
 */
const char *
pkt_type_to_str(odr_pkt_type o) {
  switch(o) {
    case PKT_RREP: return "PKT_RREP";
    case PKT_RREQ: return "PKT_RREQ";
    case PKT_DATA: return "PKT_DATA";
    default      : return "UNKNOWN";
  }
}

/* Check the queue of pending data packets to be routed, and send out
 * as many as we can.
 */
void
maybe_flush_queued_data_packets(void) {
  int i;
  odr_pkt *pkt;
  route_entry *r;
  char eth_buf[20];
  vector orphans;
  vector_init(&orphans, sizeof(odr_pkt*));
  
  VERBOSE("Entering maybe_flush_queued_data_packets()\n%s", "");
  VERBOSE("Size of odr_send_q: %d\n", vector_size(&odr_send_q));
  for (i = 0; i < vector_size(&odr_send_q); i++) {
    pkt = *(odr_pkt**)vector_at(&odr_send_q, i);
    ASSERT(pkt->type == PKT_RREQ || pkt->type == PKT_RREP || pkt->type == PKT_DATA);
    r = get_route_entry(pkt->dst_ip);
    
    if (pkt->type == PKT_DATA) {
      VERBOSE("For PKT_DATA destined to %s, the route %s\n",
              pkt->dst_ip,
              (r == NULL ? "does not exist." : "exists"));
    }

    // If a routing entry exists, flush the packet out
    if (r != NULL) {
      pkt->flags &= ~(RREQ_ALREADY_SENT_FLG);
      assert(!(pkt->flags & RREQ_ALREADY_SENT_FLG));

      pretty_print_eth_addr(r->next_hop, eth_buf); 
      VERBOSE("Found a route for a packet of type %s to IP %s, with next hop %s\n", 
              pkt_type_to_str(pkt->type),
              pkt->dst_ip,
              eth_buf);
      odr_route_message(pkt, r);
      // We need to free(3) this packet after using it.
      free(pkt);
    } else {
      if (pkt->type == PKT_DATA && (!(pkt->flags & RREQ_ALREADY_SENT_FLG))) {
        VERBOSE("Flooding the network to send the PKT_DATA orphan packet destined to %s\n",
                pkt->dst_ip);
        pkt->flags |= RREQ_ALREADY_SENT_FLG;
        odr_start_route_discovery(pkt, -1, TRUE);
      }
      vector_push_back(&orphans, &pkt);
    }
  } // for()

  vector_swap(&odr_send_q, &orphans);
  vector_destroy(&orphans);
  for (i = 0; i < vector_size(&odr_send_q); i++) {
    pkt = *(odr_pkt**)vector_at(&odr_send_q, i);
    ASSERT(pkt->type == PKT_RREQ || pkt->type == PKT_RREP || pkt->type == PKT_DATA);
  }
  
  VERBOSE("Leaving maybe_flush_queued_data_packets()\n%s", "");
}

void
process_eth_pkt(eth_frame *frame, struct sockaddr_ll *sa) {
  // TODO
  // There is a packet on the PF_PACKET sockfd
  // Process it
  char src_addr[20];
  char dst_addr[20];
  odr_pkt *pkt;
  pkt = (odr_pkt*)frame->payload;

  pretty_print_eth_addr(frame->src_eth_addr.eth_addr, src_addr);
  pretty_print_eth_addr(frame->dst_eth_addr.eth_addr, dst_addr);
  
  VERBOSE("process_eth_pkt:: (%s -> %s) of type %s\n", 
          src_addr, dst_addr, pkt_type_to_str(pkt->type));

  if (ntohs(frame->protocol) != ODR_PROTOCOL) {
    return;
  }

  odr_packet_print(pkt);

  if (should_process_packet(pkt) == FALSE) {
    return;
  }

  prune_routing_table(pkt->dst_ip, pkt->flags);
  prune_cli_table();

  if (is_my_ip(pkt->dst_ip) == TRUE) {
    VERBOSE("Received a packet meant for me\n%s", "");
    if (pkt->type == PKT_DATA) {
      odr_deliver_message_to_client(pkt);
    } else {
      assert(pkt->type == PKT_RREQ || pkt->type == PKT_RREP);
    }
  }

  if (pkt->type == PKT_RREQ || pkt->type == PKT_RREP) {
    update_routing_table(pkt, sa);
    print_routing_table();
    act_on_packet(pkt, sa);
  } else if (!is_my_ip(pkt->dst_ip) && pkt->type == PKT_DATA) {
    // Add this data packet to the queue.
    odr_pkt *p = MALLOC(odr_pkt);
    print_routing_table();
    memcpy(p, pkt, sizeof(odr_pkt));
    VERBOSE("Pushing the PKT_DATA packet into the queue\n%s", "");
    
    ASSERT(p->type == PKT_RREQ || p->type == PKT_RREP || p->type == PKT_DATA);
    vector_push_back(&odr_send_q, &p);
  }
  maybe_flush_queued_data_packets();
}

void
on_pf_recv(void *opaque) {
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  eth_frame frame;
  memset(&frame, 0, sizeof(frame));
  r = recvfrom(pf_sockfd, &frame, sizeof(frame), 0, (SA*)&sa, &addrlen);
  VERBOSE("Received an eth_frame of size %d\n", r);
  if (r < 0 && errno == EINTR) {
    VERBOSE("recvfrom got EINTR%s\n", "");
    return;
  }
  if (r < 0) {
    perror("recvfrom");
    exit(1);
  }
  assert_ge(r, 64);
  // memcpy(sa.if_haddr, frame.src_eth_addr, sizeof(sa.if_haddr));
  process_eth_pkt(&frame, &sa);
}

void
on_pf_error(void *opaque) {
  INFO("Error detected on the PF_PACKET socket. Exiting...%s\n", "");
  exit(1);
}

void
on_ud_recv(void *opaque) {
  struct sockaddr_un cliaddr;
  socklen_t clilen;
  api_msg m;
  cli_entry *c;

  clilen = sizeof(cliaddr);
  memset(&cliaddr, 0, sizeof(cliaddr));
  memset(&m, 0, sizeof(m));

  Recvfrom(s.sockfd, (char*)&m, sizeof(api_msg), 0, (SA *) &cliaddr, &clilen);
  c = get_cli_entry(&cliaddr);
  process_dsock_requests(&m, c);
}

void
on_ud_error(void *opaque) {
  INFO("Error detected on the AF_UNIX socket. Exiting...%s\n", "");
  exit(1);
}

void
on_timeout(void *opaque) {
  VERBOSE("Timed out. odr_send_q size: %d\n", vector_size(&odr_send_q));
}

void
odr_loop(void) {
  // We never come out of this function
  struct timeval timeout;
  int r;
  timeout.tv_sec = 10; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

  VERBOSE("pf_sockfd: %d\n", pf_sockfd);

  fdset_add(&fds, &fds.rev,  pf_sockfd, &pf_sockfd, on_pf_recv);
  fdset_add(&fds, &fds.exev, pf_sockfd, &pf_sockfd, on_pf_error);

  fdset_add(&fds, &fds.rev,  s.sockfd, &s.sockfd, on_ud_recv);
  fdset_add(&fds, &fds.exev, s.sockfd, &s.sockfd, on_ud_error);

  r = fdset_poll(&fds, &timeout, on_timeout);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

void on_odr_exit(void) {
  struct timeval tv;
  time_t currtime;
  char str_time[40];
  Gettimeofday(&tv, NULL);
  time(&currtime);
  strftime(str_time, 40, "%T", localtime(&currtime));
  INFO("ODR exited at %s.%03u\n", str_time, (unsigned int)tv.tv_usec/1000);
  fflush(stdout);
}

int
main(int argc, char **argv) {
  double staleness_sec;
  appname = argv[0];
  VERBOSE("Commit ID: %s\n", COMMITID);
  atexit(on_odr_exit);
  // signal(SIGSEGV, sigsegv_handler);
  signal(SIGINT,  sigint_handler);
  signal(SIGTERM, sigterm_handler);

  if (argc != 2) {
    fprintf(stderr, "Usage: ./odr <staleness>");
    exit(1);
  }
  
  sscanf(argv[1], "%lf", &staleness_sec);
  // Convert the floating point staleness value, which was 
  // in seconds to milliseconds
  staleness = (uint32_t)(1000 * staleness_sec);

  odr_setup();
  odr_loop();
  return 0;
}
