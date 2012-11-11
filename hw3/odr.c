#include "utils.h"

typedef struct serv_dsock {
  struct sockaddr_un servaddr;
  int sockfd;
} serv_dsock;

void
create_serv_dsock(serv_dsock *s) {
  if (s == NULL) {
    s = MALLOC(serv_dsock);
  }
  s->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  unlink(SRVDGPATH);
  bzero(&s->servaddr, sizeof(s->servaddr));
  s->servaddr.sun_family = AF_LOCAL;
  strcpy(s->servaddr.sun_path, SRVDGPATH);
  
  Bind(s->sockfd, (SA *) &s->servaddr, sizeof(s->servaddr));
  VERBOSE("Successfully bound to the socket\n%s", "");
}

void
process_requests(void) {
  // TODO Fill this up 
}

int
main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: ./odr <staleness>");
    exit(1);
  }
  
  serv_dsock s;
  create_serv_dsock(&s);
  return 0;
}
