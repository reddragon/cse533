#include "utils.h"
#include "api.h"

serv_dsock s;

void
odr_setup(void) {
  // TODO
  // Create the PF_PACKET socket
}

void
odr_send(api_msg *m) {
  // TODO 
  // Actual sending of the message
}

void
odr_recv(api_msg *m, struct sockaddr_un *cliaddr) {
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
  if (m.rtype == MSG_SEND) {
    odr_send(&m);
  } else if (m.rtype == MSG_RECV) {
    odr_recv(&m, cliaddr);
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
