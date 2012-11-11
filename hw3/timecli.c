// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

cli_dsock c;
char *tmp_fname = NULL;

void on_client_exit(void) {
  if (tmp_fname) {
    unlink(tmp_fname);
  }
  struct timeval tv;
  Gettimeofday(&tv, NULL);
  time_t currtime;
  char str_time[40];
  time(&currtime);
  strftime(str_time, 40, "%T", localtime(&currtime));
  INFO("Client exited at %s.%03u\n", str_time, (unsigned int)tv.tv_usec/1000);
}

void
test_api(void) {
  //msg_send(c.sockfd, "123.456.789.123", 1234, "Hello!", 0);
  char ip[20], msg[500];
  int src_port;
  msg_recv(c.sockfd, ip, &src_port, msg);
}

int
main(int argc, char **argv) {
  assert(((api_msg*)(0))->msg == API_MSG_HDR_SZ);
  atexit(on_client_exit);

  tmp_fname = create_tempfile();
  VERBOSE("Client File Name: %s\n", tmp_fname);

  create_cli_dsock(tmp_fname, &c);
  test_api();
  return 0;
}
