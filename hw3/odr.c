// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "odr.h"
#include "treap.h"
#include "fdset.h"
#include "myassert.h"

serv_dsock s;             // Domain socket to listen on & serve requests
vector cli_table;         // Table containing entries of all clients
vector route_table;       // The Routing Table
uint32_t next_e_portno;   // Next Ephemeral Port Number to assign
char my_ipaddr[16];       // My IP Address
int pf_sockfd = -1;       // Sockfd corresponding to the PF_PACKET socket
uint32_t staleness;       // Staleness paramenter
fdset fds;                // fdset for the client's domain socket
struct hwa_info *h_head;  // The hardware interfaces

cli_entry *
add_cli_entry(struct sockaddr_un *cliaddr) {
  cli_entry *e = MALLOC(cli_entry);
  e->last_id = 0;
  e->cliaddr = cliaddr;
  e->e_portno = next_e_portno++;
  vector_init(&e->pkt_queue, sizeof(odr_pkt *));
  vector_push_back(&cli_table, (void *)e);
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
get_route_entry(api_msg *m) {
  int i;
  route_entry *c = NULL;
  for (i = 0; i < vector_size(&route_table); i++) {
    route_entry *r = vector_at(&route_table, i);
    if (is_stale_entry(r) ||
        (!strcmp(r->ip_addr, m->ip) && (m->msg_flag & ROUTE_REDISCOVERY_FLG))) {
      // This is a stale entry
      vector_erase(&route_table, i);
      i--;
    } else if (!strcmp(r->ip_addr, m->ip)) {
      // We have a potential match
      c = r;
      break;
    }
  }
  return c;
}

void
odr_setup(void) {
  vector_init(&cli_table, sizeof(cli_entry));
  vector_init(&route_table, sizeof(route_entry));
  next_e_portno = 7700;
  
  h_head = Get_hw_addrs();

  struct hwa_info *h;
  for (; h != NULL; h = h->hwa_next) {
     
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
}

void
odr_route_message(api_msg *m) {
  // TODO 
  // Actual sending of the message

  // Look up the routing table, to see if there is an entry
  route_entry *r = get_route_entry(m);
  if (r != NULL) {
    // Send the message on the interface corresponding to r->iface_idx
  } else {
        
  }
}

void
odr_deliver_message_to_client(api_msg *m, cli_entry *c) {
  // TODO
  // Receive a message, and then respond to the client
  // VERBOSE("Responding to client with sun_path: %s\n", cliaddr->sun_path);
  // api_msg resp;
  // Sendto(s.sockfd, (char *) &resp, sizeof(api_msg), 0, (SA *) &cliaddr, clilen);
}

void
process_dsock_requests(void) {
  struct sockaddr_un cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  memset(&cliaddr, 0, sizeof(cliaddr));

  api_msg m;
  Recvfrom(s.sockfd, (char *) &m, sizeof(api_msg), 0, (SA *) &cliaddr, &clilen);
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m.rtype, cliaddr.sun_path);
  cli_entry *c = get_cli_entry(&cliaddr);
  if (m.rtype == MSG_SEND) {
      // odr_send(&m);
  } else if (m.rtype == MSG_RECV) {
      // odr_recv(&m, c);
  }
}

void
process_eth_pkt(eth_frame *frame) {
  // TODO
  // There is a packet on the PF_PACKET sockfd
  // Process it
  VERBOSE("process_eth_pkt::Length: %d\n", frame->length);
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
  create_serv_dsock(&s);
  odr_loop();
  return 0;
}
