#include "utils.h"
#include "api.h"

serv_dsock s;

void
process_requests(void) {
  // TODO Fill this up 
  char buff[512];
  struct sockaddr_un cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  
  api_msg m;
  int r = Recvfrom(s.sockfd, (char *) &m, sizeof(api_msg), 0, (SA *) &cliaddr, &clilen);
  VERBOSE("%d %s %s\n", m.rtype, m.msg, cliaddr.sun_path);
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
