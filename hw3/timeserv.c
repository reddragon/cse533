// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"
#include "fdset.h"
#include "myassert.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

serv_dsock s;                  // server's domain socket
fdset fds;                     // fdset for the server's domain socket

void on_server_exit(void) {
  struct timeval tv;
  time_t currtime;
  char str_time[40];

  unlink(SRV_DGPATH);
  Gettimeofday(&tv, NULL);
  time(&currtime);
  strftime(str_time, 40, "%T", localtime(&currtime));
  INFO("Server exited at %s.%03u\n", str_time, (unsigned int)tv.tv_usec/1000);
}

void on_recv_timedout(void *opaque) {
  VERBOSE("Timed out%s\n", "");
}

void on_recv(void *opaque) {
  // Received a message.
  int r;
  char src_ip[20];
  int src_port;
  char msg[30];
  time_t rawtime;
  struct tm *timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  r = msg_recv(s.sockfd, src_ip, &src_port, msg);
  if (r < 0) {
    perror("msg_recv");
    if (errno == EINTR) {
      return;
    } else {
      exit(1);
    }
  }

  INFO("Received message: '%s' from %s:%d\n", msg, src_ip, src_port);
  VERBOSE("Sending a message to the client %s:%d\n", src_ip, src_port);
  strftime(msg, sizeof(msg), "%c", timeinfo);
  r = msg_send(s.sockfd, src_ip, src_port, msg, 0);
  while (r < 0 && errno == EINTR) {
    r = msg_send(s.sockfd, src_ip, src_port, msg, 0);
  }
  assert_ge(r, 0);
}

void on_error(void *opaque) {
  INFO("Error on socket while listening for incoming data%s\n", "");
  exit(1);
}

void
server_loop(void) {
  struct timeval timeout;
  int r;

  VERBOSE("server_loop()%s\n", "");

  timeout.tv_sec = 10; // FIXME when we know better
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, NULL);

  fdset_add(&fds, &fds.rev,  s.sockfd, &s.sockfd, on_recv);
  fdset_add(&fds, &fds.exev, s.sockfd, &s.sockfd, on_error);

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
  atexit(on_server_exit);

  memset(&s, 0, sizeof(s));
  create_srv_dsock(&s);

  (void) signal(SIGINT, on_interrupt);
  server_loop();
  return 0;
}
