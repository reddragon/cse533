#include "utils.h"
#include "api.h"
#include "odr.h"

serv_dsock s;           // Domain socket to listen for & serve requests
vector cli_table;       // Table containing entries of all clients
uint32_t next_e_portno; // Next Ephemeral Port Number to assign

void
odr_setup(void) {
  vector_init(&cli_table, sizeof(cli_entry));
  next_e_portno = 7700;
  // TODO Create the PF_PACKET socket
}

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
  }
  return e;
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

  create_serv_dsock(&s);
  process_requests();
  return 0;
}
