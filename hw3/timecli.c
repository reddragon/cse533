// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "fdset.h"
#include "myassert.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

cli_dsock c;                   // client's domain socket
char *tmp_fname = NULL;        // temp-file name
fdset fds;                     // fdset for the client's domain socket
int ntimeouts = 0;             // # of timeouts for this msg_send()
char server_ip[40];            // The IP address of the server as entered by the user

void on_client_exit(void) {
  struct timeval tv;
  time_t currtime;
  char str_time[40];

  if (tmp_fname) {
    unlink(tmp_fname);
  }
  Gettimeofday(&tv, NULL);
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

void ask_for_user_input(void) {
  printf("Please enter the IP of the VM do you want to send a message to: ");
  scanf("%s", server_ip);
}

void on_recv_timedout(void *opaque) {
  if (++ntimeouts >= 2) {
    // Reset. TODO: Print timed out 2 times.
    ask_for_user_input();
    msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
  }
  // Resend message to 'server_ip' with the route re-discovery flag
  // set.
  msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 1);
}

void on_recv(void *opaque) {
  // Received a message. TODO: Print it.
  ask_for_user_input();
  msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);

  ntimeouts = 0;
}

void on_error(void *opaque) {
  printf("Error on socket while listening for incoming data\n");
  exit(1);
}

void
client_loop(void) {
  struct timeval timeout;
  int r;
  timeout.tv_sec = 10; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

  fdset_add(&fds, &fds.rev,  c.sockfd, &c.sockfd, on_recv);
  fdset_add(&fds, &fds.exev, c.sockfd, &c.sockfd, on_error);

  ask_for_user_input();
  msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);

  fdset_poll(&fds, &timeout, on_recv_timedout);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

void on_interrupt(int status) {
  exit(0);
}

int
main(int argc, char **argv) {
  assert(((api_msg*)(0))->msg == (void *)API_MSG_HDR_SZ);
  atexit(on_client_exit);

  tmp_fname = create_tempfile();
  VERBOSE("Client File Name: %s\n", tmp_fname);

  prhwaddrs();

  create_cli_dsock(tmp_fname, &c);

  (void) signal(SIGINT, on_interrupt);
  client_loop();
  test_api();
  return 0;
}
