#include "utils.h"
#include <string.h>
#include <stdlib.h>

char *
create_tempfile(void) {
  char *file_name = NMALLOC(char, 15);
  strcpy(file_name, "/tmp/dsockXXXXXX");
  int fd = mkstemp(file_name);
  assert(fd > 0);
  return file_name;
}

typedef struct cli_dsock {
  struct sockaddr_un cliaddr, servaddr;
  int sockfd;
} cli_dsock;

void
create_cli_dsock(char *file_name, cli_dsock *c) {
  if (c == NULL) {
    c = MALLOC(cli_dsock);
  }
  c->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  bzero(&c->cliaddr, sizeof(c->cliaddr));
  c->cliaddr.sun_family = AF_LOCAL;

  // We need to unlink because mkstemp will create the file for us
  unlink(file_name); 
  strcpy(c->cliaddr.sun_path, file_name);
  Bind(c->sockfd, (SA *) &c->cliaddr, sizeof(c->cliaddr));
  
  bzero(&c->servaddr, sizeof(c->servaddr));
  c->servaddr.sun_family = AF_LOCAL;
  strcpy(c->servaddr.sun_path, SRVDGPATH);
}

int
main(int argc, char **argv) {
  char *file_name = create_tempfile();
  VERBOSE("Client File Name: %s\n", file_name);
  
  cli_dsock c;
  create_cli_dsock(file_name, &c);
  return 0;
}
