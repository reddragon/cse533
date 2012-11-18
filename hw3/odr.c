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
  cli_entry *e = MALLOC(cli_entry);
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

cli_entry *
get_cli_entry(struct sockaddr_un *cliaddr) {
  int i;
  cli_entry *e = NULL;
  for (i = 0; i < vector_size(&cli_table); i++) {
    cli_entry *t = (cli_entry *) vector_at(&cli_table, i);
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
  route_entry *c = NULL;
  for (i = 0; i < vector_size(&route_table); i++) {
    route_entry *r = vector_at(&route_table, i);
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
  vector_init(&cli_table,   sizeof(cli_entry));
  vector_init(&route_table, sizeof(route_entry));
  treap_init(&iface_treap);
  treap_init(&cli_port_map);
  vector_init(&odr_send_q,  sizeof(odr_pkt*));
  next_e_portno = 7700;

  h_head = Get_hw_addrs();

  struct hwa_info *h;
  for (h = h_head; h != NULL; h = h->hwa_next) {
    treap_insert(&iface_treap, h->if_index, h);     
    if (!strcmp(h->if_name, "eth0") && h->ip_addr != NULL) {
      struct sockaddr *sa = h->ip_addr;
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
  struct sockaddr_un *serv_addr = MALLOC(struct sockaddr_un);
  strcpy(serv_addr->sun_path, SRV_DGPATH);
  serv_addr->sun_family = AF_LOCAL;
  add_cli_entry(serv_addr);
  create_serv_dsock(&s);
}

void
odr_start_route_discovery(const char *dest_ip) {
}

#if 0
  ++pkt->hop_count;
  if (pkt->hop_count >= MAX_HOP_COUNT) {
    INFO("Dropping packet from %s:%d -> %s:%d because hop count reached %d\n",
         pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->hop_count);
    free(pkt);
    return;
  }

  // Look up the routing table, to see if there is an entry
  route_entry *r = get_route_entry(pkt);
  if (r == NULL) {
    odr_start_route_discovery(pkt->dst_ip);
    // Queue up the packet to be sent later.
    vector_push_back(&odr_send_q, pkt);
    return;
  }
  // TODO: Send out this ODR packet over the network.
#endif

void
send_eth_pkt(eth_frame *ef) {
  Send(pf_sockfd, (void *)ef, sizeof(*ef), 0);     
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
  // Look up the routing table, to see if there is an entry
  route_entry *r = get_route_entry(pkt);
  if (r == NULL) {
    INFO("Could not find a route for IP Address: %s\n", pkt->src_ip);
    // We need to send an RREQ type ODR packet, wrapped
    // in an ethernet frame

    // Make a new ODR Packet
    odr_pkt rreq_pkt;
    memcpy(&rreq_pkt, pkt, sizeof(odr_pkt));
    rreq_pkt.type = RREQ;
    memset(rreq_pkt.msg, 0, sizeof(rreq_pkt.msg));

    eth_frame ef;
    memset(ef.dst_eth_addr, 0xff, sizeof(ef.dst_eth_addr));
    ef.protocol = ODR_PROTOCOL;
      
    // Copy the ODR packet 
    memcpy(ef.payload, &rreq_pkt, sizeof(rreq_pkt));

    struct hwa_info *h;
    for (h = h_head; h != NULL; h = h->hwa_next) {
      memcpy(ef.src_eth_addr, h->if_haddr, sizeof(h->if_haddr));
      send_eth_pkt(&ef);     
    }

    // Keeping the original ODR packet on the queue
    vector_push_back(&odr_send_q, pkt);
  } else {
    // We have an entry to the destination, just route it

    // TODO Handle when the hop count increases beyond a limit?
    struct hwa_info *h = (struct hwa_info *)treap_find(&iface_treap, r->iface_idx);  
    
    INFO("Found a route for IP Address: %s, which goes through my interface %s\n", pkt->src_ip, h->if_name);
    eth_frame ef;
    
    memcpy(ef.src_eth_addr, h->if_haddr, sizeof(h->if_haddr));
    memcpy(ef.dst_eth_addr, r->next_hop, sizeof(r->next_hop));
    ef.protocol = ODR_PROTOCOL;
      
    // Copy the ODR packet 
    memcpy(ef.payload, pkt, sizeof(*pkt));
    send_eth_pkt(&ef);
  }
}

/* Deliver the message 'pkt' received by the ODR to the client to
 * which it is destined. In case the client was not found, we silently
 * drop the message and print an INFO message.
 *
 */
void
odr_deliver_message_to_client(odr_pkt *pkt) {
  // TODO
  VERBOSE("odr_deliver_message_to_client:: (%s:%d) -> (%s:%d)\n",
          pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
  cli_entry *ce = (cli_entry*)treap_get_value(&cli_port_map, pkt->dst_port);
  if (!ce) {
    INFO("No entry for destination port #%d\n", pkt->dst_port);
    return;
  }

  struct sockaddr_un *cliaddr = ce->cliaddr;
  VERBOSE("odr_deliver_message_to_client::sun_path: %s\n", cliaddr->sun_path);

  if (!ce->is_blocked_on_recv) {
    INFO("Client %s:%d is NOT blocked on msg_recv()\n",
         pkt->dst_ip, pkt->dst_port);
    vector_push_back(&ce->pkt_queue, pkt);
    return;
  }

  api_msg resp;
  memset(&resp, 0, sizeof(resp));
  const socklen_t clilen = sizeof(cliaddr);
  resp.rtype = MSG_RESPONSE;
  resp.port = pkt->src_port;
  strcpy(resp.ip, pkt->src_ip);
  resp.msg_flag = 0;
  memcpy(resp.msg, pkt->msg, API_MSG_SZ);

  int r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) &cliaddr, clilen);
  while (r < 0 && errno == EINTR) {
    r = sendto(s.sockfd, (char*)&resp, sizeof(api_msg), 0, (SA*) &cliaddr, clilen);
  }
  ASSERT(r >= 0);
}

void
process_dsock_requests(api_msg *m, cli_entry *c) {
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m->rtype, c->cliaddr->sun_path);
 if (m->rtype == MSG_SEND) {
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
  socklen_t clilen = sizeof(cliaddr);
  memset(&cliaddr, 0, sizeof(cliaddr));

  api_msg *m = MALLOC(api_msg);
  Recvfrom(s.sockfd, (char *) m, sizeof(api_msg), 0, (SA *) &cliaddr, &clilen);
  cli_entry *c = get_cli_entry(&cliaddr);
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
  timeout.tv_sec = 10; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

  fdset_add(&fds, &fds.rev,  pf_sockfd, &pf_sockfd, on_pf_recv);
  fdset_add(&fds, &fds.exev, pf_sockfd, &pf_sockfd, on_pf_error);

  fdset_add(&fds, &fds.rev,  s.sockfd, &s.sockfd, on_ud_recv);
  fdset_add(&fds, &fds.exev, s.sockfd, &s.sockfd, on_ud_error);

  int r = fdset_poll(&fds, NULL, NULL);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

void on_odr_exit(void) {
  struct timeval tv;
  Gettimeofday(&tv, NULL);
  time_t currtime;
  char str_time[40];
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
