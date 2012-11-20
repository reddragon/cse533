// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "odr.h"
#include "treap.h"
#include "fdset.h"
#include "myassert.h"
#include "gitcommit.h"

/* TODO: We also need to time out older clients that don't exist. We
 * can possibly do this by checking if the socket file for that client
 * exists or not.
 */

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
int broadcast_id = 1;     // The global broadcast ID we use for RREQ and RREP packets. Remember to initialize to a random value.
vector bid_table;         // The ID containing the mapping of IP to Broadcast ID

/* Print out the routing table */
void
print_route_table(void) {
  int i;
  route_entry *e;
  char buff[20];
  printf("Routing Table:\n");
  for (i = 0; i < vector_size(&route_table); ++i) {
    pretty_print_eth_addr(e->next_hop, buff);
    e = (route_entry*)vector_at(&route_table, i);
    printf("To '%s' via '%s'\n", e->ip_addr, buff);
  }
}

/* Add an entry to the cli_table, which holds a list of cli_entry's
 * for every client that has contacted us.
 */
cli_entry *
add_cli_entry(struct sockaddr_un *cliaddr) {
  cli_entry *e;
  e = MALLOC(cli_entry);
  e->last_id = 0;
  e->cliaddr = cliaddr;
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
    struct sockaddr_un *caddr = MALLOC(struct sockaddr_un);
    memcpy(caddr, cliaddr, sizeof(*cliaddr));
    e = add_cli_entry(caddr);
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
get_route_entry(odr_pkt *p) {
  int i;
  route_entry *c = NULL, *r;
  for (i = 0; i < vector_size(&route_table); i++) {
    r = vector_at(&route_table, i);
    if (is_stale_entry(r) ||
        (!strcmp(r->ip_addr, p->dst_ip) && (p->flags & ROUTE_REDISCOVERY_FLG))) {
      // This is a stale entry
      vector_erase(&route_table, i);
      i--;
    } else if (!strcmp(r->ip_addr, p->dst_ip)) {
      // We have a potential match
      c = r;
      break;
    }
  }
  return c;
}

void
odr_packet_print(odr_pkt *pkt) {
  INFO("ODR Packet { Type: %d, bcast_id: %d, hop_count: %d, src: %s:%d, "
       "dst: %s:%d, size: %d }\n",
       pkt->type, pkt->broadcast_id, pkt->hop_count,
       pkt->src_ip, pkt->src_port,
       pkt->dst_ip, pkt->dst_port, pkt->msg_size);
}

void
odr_setup(void) {
  struct hwa_info *h;
  struct sockaddr *sa;
  struct sockaddr_un *serv_addr;
  int r;
  unsigned int seed;
  FILE *pf;

  vector_init(&cli_table,   sizeof(cli_entry));
  vector_init(&route_table, sizeof(route_entry));
  vector_init(&bid_table, sizeof(bid_entry));
  treap_init(&iface_treap);
  treap_init(&cli_port_map);
  vector_init(&odr_send_q,  sizeof(odr_pkt*));
  next_e_portno = 7700;

  pf = fopen("/dev/urandom", "r");
  assert(pf);
  r = fread(&seed, sizeof(seed), 1, pf);
  assert(r == 1);
  srand(seed);
  fclose(pf);
  pf = NULL;

  broadcast_id = rand() % 10000;

  h_head = Get_hw_addrs();

  for (h = h_head; h != NULL; h = h->hwa_next) {
    treap_insert(&iface_treap, h->if_index, h);
    if (!strcmp(h->if_name, "eth0") && h->ip_addr != NULL) {
      sa = h->ip_addr;
      strcpy(my_ipaddr, (char *)Sock_ntop_host(sa, sizeof(*sa)));
      INFO("My IP Address: %s\n", my_ipaddr);
    }
    
    if (strcmp(h->if_name, "lo") && strncmp(h->if_name, "eth0", 4)) {
      INFO("Discovered interface: %s\n", h->if_name);
    }
  }

  // Create the PF_PACKET socket
  pf_sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ODR_PROTOCOL));
  VERBOSE("Sucessfully created the PF_PACKET socket\n%s", "");
  serv_addr = MALLOC(struct sockaddr_un);
  r = mkdir("/tmp/dynamic_duo/", 0755);
  strcpy(serv_addr->sun_path, SRV_DGPATH);
  serv_addr->sun_family = AF_LOCAL;
  add_cli_entry(serv_addr);
  create_serv_dsock(&s);
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
odr_start_route_discovery(odr_pkt *pkt) {
  // We need to send a PKT_RREQ type ODR packet, wrapped
  // in an ethernet frame

  // Make a new ODR Packet
  odr_pkt rreq_pkt;
  eth_addr_t src_addr, dst_addr;
  struct hwa_info *h;
  int odr_pkt_hdr_sz;

  rreq_pkt = *pkt;
  rreq_pkt.type = PKT_RREQ;
  rreq_pkt.broadcast_id = pkt->broadcast_id;

  // Zero out the data.
  memset(rreq_pkt.msg, 0,   sizeof(rreq_pkt.msg));
  memset(dst_addr.eth_addr, 0xff, sizeof(dst_addr));
  odr_pkt_hdr_sz = (int)(((odr_pkt*)(0))->msg);

  VERBOSE("odr_start_route_discovery::Flooding the network with a PKT_RREQ for destination IP: %s\n", pkt->dst_ip);
  for (h = h_head; h != NULL; h = h->hwa_next) {
    // We don't send the message on eth0 and its aliases, and lo
    if (!strncmp(h->if_name, "eth0", 4) || !strcmp(h->if_name, "lo")) {
      continue;
    }

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
    INFO("Dropping a PKT_RREQ packet from %s:%d -> %s:%d with broadcast_id: %d, because I have seen it earlier\n",
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

  // We got a request packet from someone. Update the reverse path
  // to that host as via the host we got this packet from.
  e = get_route_entry(pkt);
  if (!e) {
    INFO("New routing table entry to %s via %s\n", pkt->src_ip, via_eth_addr);
    // We have a new routing table entry.
    e = MALLOC(route_entry);
    memcpy(e->ip_addr, pkt->src_ip, sizeof(e->ip_addr));
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
      memcpy(e->ip_addr, pkt->src_ip, sizeof(e->ip_addr));
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

  pretty_print_eth_addr((char*)from->sll_addr, via_eth_addr);

  VERBOSE("act_on_packet::(%s -> %s); hop_count: %d; via: %s\n",
          pkt->src_ip, pkt->dst_ip, pkt->hop_count, via_eth_addr);

  if (pkt->type != PKT_RREQ && pkt->type != PKT_RREP) {
    // Ignore this packet since it is neither an RREQ nor is it an
    // RREP.
    VERBOSE("Ignoring packet since it is of type: %d\n", pkt->type);
    return;
  }

  if (pkt->type == PKT_RREQ) {
    // TODO: If this packet's destination IP is our IP OR we have an
    // un-expired route to the destination, we reply with a
    // PKT_RREP. Otherwise, we re-broadcast this RREQ.
    e = get_route_entry(pkt);
    if (is_my_packet(pkt) || e) {
      VERBOSE("The miracle, RREQ -> RREP conversion.%s\n", "");
      odr_send_rrep(pkt, e, from);
    } else {
      odr_start_route_discovery(pkt);
    }
  } else {
    // PKT_RREP (FIXME)
    //
    // Propagate this RREP packet to the next hop on the path to the
    // destination if a path to the destination is available. If such
    // a path isn't available, we flood the interfaces of this machine
    // with an RREQ to try and discover a path to the destination.
  }
}

/* Send an RREP packet when an RREQ packet is received OR when we are
 * propagating an RREP that we received.
 * 1. Create a new odr_pkt *
 * 2. Fill up the details
 * 3. Transmit it over the wire
 * 4. Free the odr_pkt *
 */
void
odr_send_rrep(odr_pkt *pkt, route_entry *e, struct sockaddr_ll *from) {
  odr_pkt *rrep_pkt;
  eth_addr_t outgoing_addr;
  eth_addr_t src_addr;

  assert(pkt->type == PKT_RREQ);

  rrep_pkt = MALLOC(odr_pkt);
  memset(rrep_pkt, 0, sizeof(rrep_pkt));
  rrep_pkt->type          = PKT_RREP;
  // No need to set the broadcast_id for an RREP.

  // If we are sending a RREP to A, which wants the path to B,
  // which goes through this node, then the hop count for A, would be:
  // hop count uptil this node + 1 (which is this node).
  rrep_pkt->hop_count     = (is_my_packet(pkt) ? 0 : e->nhops_to_dest) + 1;
  strcpy(rrep_pkt->src_ip, my_ipaddr);
  // The source of the original packet becomes the destination
  strcpy(rrep_pkt->dst_ip, pkt->src_ip);
  // TODO Retain the Route Discovery Flag?
  rrep_pkt->flags = pkt->flags;
  
  strcpy(outgoing_addr.eth_addr, 
          ((struct hwa_info *)treap_find(&iface_treap, e->iface_idx))->if_haddr);
  strcpy(src_addr.eth_addr, (char*)from->sll_addr);
  send_over_ethernet(src_addr, outgoing_addr, (void *)rrep_pkt, sizeof(*rrep_pkt), from->sll_ifindex);
  free(rrep_pkt);
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

  if (!r) {
    // Look up the routing table, to see if there is an entry
    r = get_route_entry(pkt);
    if (r == NULL) {
      INFO("Could not find a route for IP Address: %s\n", pkt->dst_ip);
      odr_start_route_discovery(pkt);

      p = MALLOC(odr_pkt);
      memcpy(p, pkt, sizeof(odr_pkt));
      // Queue up the packet to be sent later.
      vector_push_back(&odr_send_q, p);
      return;
    }
  }

  h = (struct hwa_info *)treap_find(&iface_treap, r->iface_idx);

  INFO("Found a route for IP Address: %s, which goes through my interface %s\n", pkt->dst_ip, h->if_name);

  memcpy(src_addr.eth_addr, h->if_haddr, sizeof(h->if_haddr));
  memcpy(dst_addr.eth_addr, r->next_hop, sizeof(r->next_hop));

  send_over_ethernet(src_addr, dst_addr, pkt, sizeof(*pkt), h->if_index);
  // Don't free(3) the packet here, since the caller will free it.
}

/* Is this ODR packet meant for some client on this machine?
 */
BOOL
is_my_packet(odr_pkt *pkt) {
  VERBOSE("is_my_packet(other: %s, mine: %s)\n", pkt->dst_ip, my_ipaddr);
  return strcmp(pkt->dst_ip, my_ipaddr) == 0;
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
  clilen = sizeof(cliaddr);
  resp.rtype = MSG_RESPONSE;
  resp.port = pkt->src_port;
  strcpy(resp.ip, pkt->src_ip);
  resp.msg_flag = 0;
  memcpy(resp.msg, pkt->msg, API_MSG_SZ);

  r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) &cliaddr, clilen);
  while (r < 0 && errno == EINTR) {
    r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) &cliaddr, clilen);
  }
  ASSERT(r == sizeof(api_msg));
}

odr_pkt *
create_odr_pkt(api_msg *m) {
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
  }
  o->flags = m->msg_flag;
  strcpy(o->msg, m->msg);
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
    pkt = create_odr_pkt(m);
    odr_route_message(pkt, NULL);
    free(pkt);
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
  vector orphans;
  vector_init(&orphans, sizeof(odr_pkt*));

  for (i = 0; i < vector_size(&odr_send_q); i++) {
    pkt = vector_at(&odr_send_q, i);
    r = get_route_entry(pkt);

    // If a routing entry exists, flush the packet out
    if (r != NULL) {
      odr_route_message(pkt, r);
      // We need to free(3) this packet after using it.
      free(pkt);
    } else {
      vector_push_back(&orphans, pkt);
    }
  } // for()

  vector_swap(&odr_send_q, &orphans);
  vector_destroy(&orphans);
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

  VERBOSE("process_eth_pkt:: (%s -> %s)\n", src_addr, dst_addr);

  if (ntohs(frame->protocol) != ODR_PROTOCOL) {
    return;
  }

  odr_packet_print(pkt);

  if (should_process_packet(pkt) == FALSE) {
    return;
  }

  if (is_my_packet(pkt) == TRUE) {
    VERBOSE("Received a packet meant for me\n%s", "");
    if (pkt->type == PKT_DATA) {
      odr_deliver_message_to_client(pkt);
    } else {
      assert(pkt->type == PKT_RREQ || pkt->type == PKT_RREP);
    }
  }

  if (pkt->type == PKT_RREQ || pkt->type == PKT_RREP) {
    update_routing_table(pkt, sa);
    act_on_packet(pkt, sa);
  } else {
    // Add this data packet to the queue.
    odr_pkt *p = MALLOC(odr_pkt);
    memcpy(p, pkt, sizeof(odr_pkt));
    vector_push_back(&odr_send_q, p);
  }
  maybe_flush_queued_data_packets();
}

void
on_pf_recv(void *opaque) {
  int r;
  struct sockaddr_ll sa;
  socklen_t addrlen = sizeof(sa);
  eth_frame frame;
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

  r = fdset_poll(&fds, NULL, NULL);
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
}

int
main(int argc, char **argv) {
  VERBOSE("Commit ID: %s\n", COMMITID);
  atexit(on_odr_exit);
  if (argc != 2) {
    fprintf(stderr, "Usage: ./odr <staleness>");
    exit(1);
  }
  sscanf(argv[1], "%u", &staleness);

  odr_setup();
  odr_loop();
  return 0;
}
