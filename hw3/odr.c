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
treap iface_treap;        // Interface Index to Interface Mapping
treap cli_port_map;       // Mapping from port # to cli_entry

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
odr_setup(void) {
  struct hwa_info *h;
  struct sockaddr *sa;
  struct sockaddr_un *serv_addr;
  vector_init(&cli_table,   sizeof(cli_entry));
  vector_init(&route_table, sizeof(route_entry));
  treap_init(&iface_treap);
  treap_init(&cli_port_map);
  vector_init(&odr_send_q,  sizeof(odr_pkt*));
  next_e_portno = 7700;

  h_head = Get_hw_addrs();

  for (h = h_head; h != NULL; h = h->hwa_next) {
    treap_insert(&iface_treap, h->if_index, h);     
    if (!strcmp(h->if_name, "eth0") && h->ip_addr != NULL) {
      sa = h->ip_addr;
      strcpy(my_ipaddr, (char *)Sock_ntop_host(sa, sizeof(*sa)));
      INFO("My IP Address: %s\n", my_ipaddr);
    }
    
    if (strcmp(h->if_name, "lo") && strcmp(h->if_name, "eth0")) {
      INFO("Discovered interface: %s\n", h->if_name);
    }
  }

  // Create the PF_PACKET socket
  pf_sockfd = Socket(PF_PACKET, SOCK_DGRAM, ODR_PROTOCOL);
  VERBOSE("Sucessfully created the PF_PACKET socket\n%s", "");
  serv_addr = MALLOC(struct sockaddr_un);
  strcpy(serv_addr->sun_path, SRV_DGPATH);
  serv_addr->sun_family = AF_LOCAL;
  add_cli_entry(serv_addr);
  create_serv_dsock(&s);
}

void
send_over_ethernet(char from[6], char to[6], void *data, int len) {
  eth_frame ef;
  memcpy(ef.dst_eth_addr, to,   sizeof(ef.dst_eth_addr));
  memcpy(ef.src_eth_addr, from, sizeof(ef.src_eth_addr));
  ef.protocol = ODR_PROTOCOL;

  // Copy the payload
  memcpy(ef.payload, &data, len);
  send_eth_pkt(&ef);
}

/* Start the process of route discovery. This function floods all the
 * interfaces with an RREQ packet with the destination address set as
 * 0xff:ff:ff:ff:ff:ff.
 *
 */
void
odr_start_route_discovery(odr_pkt *pkt) {
  // We need to send an RREQ type ODR packet, wrapped
  // in an ethernet frame

  // Make a new ODR Packet
  odr_pkt rreq_pkt;
  char dest_addr[6];
  struct hwa_info *h;
  int odr_pkt_hdr_sz;

  rreq_pkt = *pkt;
  rreq_pkt.type = RREQ;
  // Zero out the data.
  memset(rreq_pkt.msg, 0, sizeof(rreq_pkt.msg));
  memset(dest_addr, 0xff, sizeof(dest_addr));
  odr_pkt_hdr_sz = (int)(((odr_pkt*)(0))->msg);

  for (h = h_head; h != NULL; h = h->hwa_next) {
    send_over_ethernet(h->if_haddr, dest_addr, &rreq_pkt, odr_pkt_hdr_sz, h->if_index);
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
send_eth_pkt(eth_frame *ef, uint16_t iface_idx) {
  struct sockaddr_ll sa;
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = ef->protocol;
  sa.sll_ifindex = iface_idx;
  sa.sll_halen = 6; // TODO Looks right?
  sa.sll_addr = ef->dst_eth_addr;
  Send(pf_sockfd, (void *)ef, sizeof(*ef), 0);
}

/* Update the routing table based on the type of the packet and the
 * source & destination addresses.
 */
void
update_routing_table(odr_pkt *pkt, struct sockaddr_ll *from) {
  if (pkt->type != RREQ && pkt->type != RREP) {
    // Ignore this packet since it is neither an RREQ nor is it an
    // RREP.
    return;
  }

  // We got a request packet from someone. Update the reverse path
  // to that host as via the host we got this packet from.
  route_entry *e = get_route_entry(pkt);
  if (!e) {
    // We have a new routing table entry.
    e = MALLOC(route_entry);
    memcpy(e->ip_addr, pkt->src_ip, sizeof(e->ip_addr));
    // e->iface_idx = TODO.
    // memcpy(e->next_hop, BLAH, sizeof(e->next_hop));
    e->nhops_to_dest = pkt->hop_count;
    e->last_updated_at_ms = current_time_in_ms();
    vector_push_back(&route_table, e);
    free(e);
  } else {
    if (e->nhops_to_dest > pkt->hop_count) {
      // Replace the older entry.
      int index = (e - (route_entry*)vector_at(&route_table, 0)) / sizeof(route_entry);
      vector_erase(&route_table, index);
      update_routing_table(pkt, from);
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

  // Look up the routing table, to see if there is an entry
  r = get_route_entry(pkt);
  if (r == NULL) {
    INFO("Could not find a route for IP Address: %s\n", pkt->src_ip);
    odr_start_route_discovery(pkt);

    // Queue up the packet to be sent later.
    vector_push_back(&odr_send_q, pkt);
    return;
  }

  h = (struct hwa_info *)treap_find(&iface_treap, r->iface_idx);

  INFO("Found a route for IP Address: %s, which goes through my interface %s\n", pkt->src_ip, h->if_name);

  send_over_ethernet(h->if_haddr, r->next_hop, pkt, sizeof(*pkt), h->if_index);
  // TODO We can free pkt here?
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
    INFO("Client %s:%d is NOT blocked on msg_recv()\n",
         pkt->dst_ip, pkt->dst_port);
    vector_push_back(&ce->pkt_queue, pkt);
    return;
  }

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
  ASSERT(r >= 0);
}

odr_pkt *
create_odr_pkt(api_msg *m) {
  odr_pkt *o;
  o = MALLOC(odr_pkt);
  o->type = DATA;
  // FIXME
  // What do we put here? 
  // Is the broadcast_id a number which increases everytime we
  // get a send request? Or is it a client specific count?
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
process_eth_pkt(eth_frame *frame) {
  // TODO
  // There is a packet on the PF_PACKET sockfd
  // Process it
  VERBOSE("process_eth_pkt::\n%s", "");
}

void
on_pf_recv(void *opaque) {
  
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
