#include "utils.h"

serv_dsock s;

void
process_requests(void) {
  // TODO Fill this up 
  char buff[512];
  struct sockaddr cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  int r = Recvfrom(s.sockfd, buff, 512, 0, &cliaddr, &clilen);
  fprintf(stderr, "%d %s\n", r, buff);
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
