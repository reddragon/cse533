// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "fdset.h"
#include "myassert.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

// FIXME: Set this to 2 before submitting.
#define MAX_TIMEOUTS 1

cli_dsock c;                   // client's domain socket
char *tmp_fname = NULL;        // temp-file name
fdset fds;                     // fdset for the client's domain socket
int ntimeouts = 0;             // # of timeouts for this msg_send()
char server_ip[80];            // The IP address of the server as entered by the user

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

void ask_for_user_input(void) {
  char hostname[100];
  char *ip = NULL;
  do {
    printf("Please enter the hostname of the VM (vm1, vm2, vm3, ..., vm10) you want to send a message to: ");
    scanf("%s", hostname);
    ip = hostname_to_ip_address(hostname, server_ip);
    if (!ip) {
      INFO("Invalid hostname '%s' entered\n", hostname);
    }
  } while (!ip);
}

void on_recv_timedout(void *opaque) {
  ++ntimeouts;
  INFO("msg_recv() timed out %d times\n", ntimeouts);
  if (ntimeouts >= MAX_TIMEOUTS) {
    // Reset. Print timed out 2 times.
    ntimeouts = 0;
    ask_for_user_input();
    msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
    return;
  }
  // Resend message to 'server_ip' with the route re-discovery flag
  // set.
  INFO("Re-sending request to %s:%d\n", server_ip, TIME_SERVER_PORT);
  msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 1);
}

void on_recv(void *opaque) {
  // Received a message.
  int r;
  char src_ip[20];
  int src_port;
  char msg[2048];

  r = msg_recv(c.sockfd, src_ip, &src_port, msg);
  if (r < 0) {
    perror("msg_recv");
    if (errno == EINTR) {
      return;
    } else {
      exit(1);
    }
  }

  INFO("Received message: '%s' from %s:%d\n", msg, src_ip, src_port);
  ask_for_user_input();
  INFO("Sending a time request to IP address: %s\n", server_ip);
  r = msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
  while (r < 0 && errno == EINTR) {
    r = msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
  }
  assert_ge(r, 0);

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

  VERBOSE("Connecting to ODR...%s\n", "");
  r = msg_connect_to_odr(c.sockfd);
  while (r < 0 && errno == EINTR) {
    r = msg_connect_to_odr(c.sockfd);
  }
  assert_ge(r, 0);

  ask_for_user_input();
  INFO("Sending a time request to IP address: %s\n", server_ip);

  r = msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
  while (r < 0 && errno == EINTR) {
    r = msg_send(c.sockfd, server_ip, TIME_SERVER_PORT, "1", 0);
  }
  assert_ge(r, 0);

  r = fdset_poll(&fds, &timeout, on_recv_timedout);
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

  create_cli_dsock(tmp_fname, &c);

  (void) signal(SIGINT, on_interrupt);
  client_loop();
  return 0;
}
