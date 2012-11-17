#include "utils.h"
#include "api.h"
#include "odr.h"
#include "treap.h"

serv_dsock s;           // Domain socket to listen on & serve requests
vector cli_table;       // Table containing entries of all clients
vector route_table;     // The Routing Table
uint32_t next_e_portno; // Next Ephemeral Port Number to assign
char my_ipaddr[16];     // My IP Address
int pf_sockfd = -1;     // Sockfd corresponding to the PF_PACKET socket
uint32_t staleness;     // Staleness paramenter

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
  int i, nentries = vector_size(&cli_table);
  cli_entry *e = NULL;
  for (i = 0; i < nentries; i++) {
    cli_entry *t = (cli_entry *) vector_at(&cli_table, i);
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

route_entry *
get_route_entry(char* target_ip_addr) {
  int i, nentries = vector_size(&route_table);
  route_entry *c = NULL;
  for (i = 0; i < nentries; i++) {
    route_entry *r = vector_at(&route_table, i);
    if (!strcmp(r->ip_addr, target_ip_addr)) {
      if (is_stale_entry(r)) {
        // This is a stale entry
        vector_erase(&route_table, i);
        break;
      }

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
  
  struct hwa_info *h = Get_hw_addrs();
  // TODO Create the PF_PACKET socket

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
  pf_sockfd = Socket(PF_PACKET, SOCK_DGRAM, ODR_PROTOCOL);
  VERBOSE("Sucessfully created the PF_PACKET socket\n%s", "");
  struct sockaddr_un *serv_addr = MALLOC(struct sockaddr_un);
  strcpy(serv_addr->sun_path, SRV_DGPATH);
  serv_addr->sun_family = AF_LOCAL;
  add_cli_entry(serv_addr);
}

void
odr_send(api_msg *m) {
  // TODO 
  // Actual sending of the message

  // Look up the routing table, to see if there is an entry
}

void
odr_recv(api_msg *m, cli_entry *c) {
  // TODO
  // Receive a message, and then respond to the client
  // VERBOSE("Responding to client with sun_path: %s\n", cliaddr->sun_path);
  // api_msg resp;
  // Sendto(s.sockfd, (char *) &resp, sizeof(api_msg), 0, (SA *) &cliaddr, clilen);
}

void
process_dsock_requests(void) {
  struct sockaddr_un *cliaddr = MALLOC(struct sockaddr_un);
  socklen_t clilen = sizeof(*cliaddr);
  
  api_msg m;
  Recvfrom(s.sockfd, (char *) &m, sizeof(api_msg), 0, (SA *) cliaddr, &clilen);
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m.rtype, cliaddr->sun_path);
  cli_entry *c = get_cli_entry(cliaddr); 
  if (m.rtype == MSG_SEND) {
    odr_send(&m);
  } else if (m.rtype == MSG_RECV) {
    odr_recv(&m, c);
  }
}

void
process_eth_pkts(void) {
  // TODO
  // There is a packet on the PF_PACKET sockfd
  // Process it
}

void
serve(void) {
  // We never come out of this function
    
}

int
main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: ./odr <staleness>");
    exit(1);
  }
  sscanf(argv[1], "%u", &staleness);

  odr_setup();
  create_serv_dsock(&s);
  serve();
  return 0;
}
