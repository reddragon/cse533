// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "odr.h"

serv_dsock s;           // Domain socket to listen for & serve requests
vector cli_table;       // Table containing entries of all clients
uint32_t next_e_portno; // Next Ephemeral Port Number to assign
char my_ipaddr[16];     // My IP Address
int pf_sockfd;          // Sockfd corresponding to the PF_PACKET socket

cli_entry *
add_cli_entry(struct sockaddr_un *cliaddr) {
  int i, nentries = vector_size(&cli_table);
  BOOL found = FALSE;
  cli_entry *e;
  for (i = 0; i < nentries; i++) {
    cli_entry *t = (cli_entry *) vector_at(&cli_table, i);
    if (!strcmp(t->cliaddr->sun_path, cliaddr->sun_path)) {
      found = TRUE;
      e = t;
      break;
    }
  }
  if (!found) {
    // Add an entry for this client
    e = MALLOC(cli_entry);
    e->last_id = 0;
    e->cliaddr = cliaddr;
    e->e_portno = next_e_portno++;
    vector_push_back(&cli_table, (void *)e);
    VERBOSE("Added an entry for client with sun_path: %s and port number: %d\n", cliaddr->sun_path, e->e_portno);
  }
  return e;
}

void
odr_setup(void) {
  vector_init(&cli_table, sizeof(cli_entry));
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
      INFO("Discovered an interface: %s\n", h->if_name);
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
odr_pkt_init(odr_pkt *pkt) {
    memset(pkt, 0, sizeof(odr_pkt));
}

void
process_requests(void) {
  struct sockaddr_un *cliaddr = MALLOC(struct sockaddr_un);
  socklen_t clilen = sizeof(*cliaddr);
  
  api_msg m;
  Recvfrom(s.sockfd, (char *) &m, sizeof(api_msg), 0, (SA *) cliaddr, &clilen);
  VERBOSE("Received a request of type %d from Client with sun_path %s\n", m.rtype, cliaddr->sun_path);
  cli_entry *c = add_cli_entry(cliaddr); 
  if (m.rtype == MSG_SEND) {
    odr_send(&m);
  } else if (m.rtype == MSG_RECV) {
    odr_recv(&m, c);
  }
}

int
main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: ./odr <staleness>");
    exit(1);
  }
  
  odr_setup();
  create_serv_dsock(&s);
  // TODO Probably multi-thread this
  // process_requests();
  return 0;
}
