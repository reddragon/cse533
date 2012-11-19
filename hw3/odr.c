// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "odr.h"
#include "treap.h"
#include "fdset.h"
#include "myassert.h"

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
  vector_init(&e->pkt_queue, sizeof(odr_pkt *));
  e->is_blocked_on_recv = FALSE;

  vector_push_back(&cli_table, (void *)e);
  treap_insert(&cli_port_map, e->e_portno, e);

  VERBOSE("Added an entry for client with sun_path: %s and port number: %d\n", cliaddr->sun_path, e->e_portno);
  return e;
}

/* Fetch a cli_entry from the cli_table given a 'struct sockaddr_un'
 * for that client address.
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

BOOL
should_process_packet(odr_pkt *pkt) {
  ++pkt->hop_count;
  if (pkt->hop_count >= MAX_HOP_COUNT) {
    INFO("Dropping packet from %s:%d -> %s:%d because hop count reached %d\n",
         pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->hop_count);
    // TODO: Caller free(3)s packet.
    // free(pkt);
    return FALSE;
  }
  return TRUE;
}

void
send_eth_pkt(eth_frame *ef, int iface_idx) {
  struct sockaddr_ll sa;

  memset(&sa, 0, sizeof(sa));
  sa.sll_family   = PF_PACKET;
  sa.sll_hatype   = ARPHRD_ETHER;
  sa.sll_pkttype  = PACKET_BROADCAST; // FIXME
  sa.sll_protocol = ef->protocol;
  sa.sll_ifindex  = iface_idx;
  sa.sll_halen    = 6; // TODO Looks right?
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

  VERBOSE("update_routing_table:: (%s -> %s); hop_count: %d; via: %s\n",
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
    e->broadcast_id       = pkt->broadcast_id;
    vector_push_back(&route_table, e);
    free(e);
  } else {
    // Check if the broadcast ID is the same.
    if (e->broadcast_id == pkt->broadcast_id) {
      // Ignore this packet.
      VERBOSE("broadcast_id [%d] matches. Stopping RREQ propagation.\n", e->broadcast_id);
      return;
    }

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
      e->broadcast_id       = pkt->broadcast_id;

      // TODO: Check if this packet's destination IP is our IP. If so,
      // don't re-broadcast the PKT_RREQ.
      if (is_my_packet(pkt)) {
        VERBOSE("This packet is for me.%s\n", "");
        return;
      }

      // TODO: Re-broadcast this packet to other interfaces on this
      // machine.
      odr_start_route_discovery(pkt);
    }
  }
}

/* Route the message 'pkt' to the appropriate recipient by computing
 * the next hop on the route. Also increment the hop_count. If the hop
 * count reaches MAX_HOP_COUNT, we silently drop this packet and print
 * out an INFO statement.
 *
 */
void
odr_route_message(odr_pkt *pkt) {
  // TODO Where are we handling RREQs and RREPs
  route_entry *r;
  struct hwa_info *h;
  eth_addr_t src_addr, dst_addr;

  // Look up the routing table, to see if there is an entry
  r = get_route_entry(pkt);
  if (r == NULL) {
    INFO("Could not find a route for IP Address: %s\n", pkt->dst_ip);
    odr_start_route_discovery(pkt);

    // Queue up the packet to be sent later.
    vector_push_back(&odr_send_q, pkt);
    return;
  }

  h = (struct hwa_info *)treap_find(&iface_treap, r->iface_idx);

  INFO("Found a route for IP Address: %s, which goes through my interface %s\n", pkt->dst_ip, h->if_name);

  memcpy(src_addr.eth_addr, h->if_haddr, sizeof(h->if_haddr));
  memcpy(dst_addr.eth_addr, r->next_hop, sizeof(r->next_hop));

  send_over_ethernet(src_addr, dst_addr, pkt, sizeof(*pkt), h->if_index);
  // TODO We can free pkt here?
}

/* Is this ODR packet meant for some client on this machine?
 */
BOOL
is_my_packet(odr_pkt *pkt) {
  return strcmp(pkt->dst_ip, my_ipaddr) == 0;
}

/* Deliver the message 'pkt' received by the ODR to the client to
 * which it is destined. In case the client was not found, we silently
 * drop the message and print an INFO message.
 *
 */
void
odr_deliver_message_to_client(odr_pkt *pkt) {
  // TODO
  cli_entry *ce;
  struct sockaddr_un *cliaddr;
  api_msg resp;
  socklen_t clilen;
  int r;
  VERBOSE("odr_deliver_message_to_client:: (%s:%d) -> (%s:%d)\n",
          pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
  ce = (cli_entry*)treap_get_value(&cli_port_map, pkt->dst_port);
  if (!ce) {
    INFO("No entry for destination port #%d\n", pkt->dst_port);
    return;
  }

  cliaddr = ce->cliaddr;
  VERBOSE("odr_deliver_message_to_client::sun_path: %s\n", cliaddr->sun_path);

  if (!ce->is_blocked_on_recv) {
    odr_pkt *p = NULL;
    INFO("Client %s:%d is NOT blocked on msg_recv()\n",
         pkt->dst_ip, pkt->dst_port);
    p = MALLOC(odr_pkt);
    memcpy(p, pkt, sizeof(odr_pkt));
    vector_push_back(&ce->pkt_queue, p);
    return;
  }

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
  ce->is_blocked_on_recv = FALSE;
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
  // The broadcast_id is probably useful only in case of an RREQ or
  // RREP packet.
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
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m->rtype, c->cliaddr->sun_path);
  if (m->rtype == MSG_SEND) {
    odr_pkt *o = create_odr_pkt(m);
    odr_route_message(o);
    // odr_send(&m);
  } else if (m->rtype == MSG_RECV) {
    // odr_recv(&m, c);
  }
  // api_msg is no longer required
  free(m);
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
    if (pkt->type == PKT_DATA) {
      odr_deliver_message_to_client(pkt);
    } else {
      assert(pkt->type == PKT_RREQ || pkt->type == PKT_RREP);
    }
  }

  update_routing_table(pkt, sa);
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
  api_msg *m;
  cli_entry *c;

  clilen = sizeof(cliaddr);
  memset(&cliaddr, 0, sizeof(cliaddr));

  m = MALLOC(api_msg);
  Recvfrom(s.sockfd, (char *) m, sizeof(api_msg), 0, (SA *) &cliaddr, &clilen);
  c = get_cli_entry(&cliaddr);
  process_dsock_requests(m, c);
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
