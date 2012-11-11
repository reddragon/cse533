#include "utils.h"
#include "api.h"

serv_dsock s;

void
process_requests(void) {
  // TODO Fill this up 
  char buff[512];
  struct sockaddr cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  
  api_msg m;
  int r = Recv(s.sockfd, (char *) &m, sizeof(api_msg), 0);
  fprintf(stderr, "%d %s\n", m.rtype, m.msg);
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
