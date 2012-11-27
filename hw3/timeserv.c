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
char my_hostname[200];         // My hostname (i.e. hostname of IP bound to eth0)
char my_ipaddr[16];            // My IP Address

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
  // FIXME: Change to VERBOSE
  INFO("Timed out%s\n", "");
}

void on_recv(void *opaque) {
  // Received a message.
  int r;
  char src_ip[20];
  char src_hostname[200];
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

  src_hostname[0] = '\0';
  ip_address_to_hostname(src_ip, src_hostname);

  INFO("server at node %s responding to request from %s:%d\n",
       my_hostname, src_hostname, src_port);

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

void server_setup(void) {
  struct hwa_info *h;
  struct hwa_info *h_head;
  struct sockaddr *sa;

  h_head = Get_hw_addrs();
  for (h = h_head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0") && h->ip_addr != NULL) {
      sa = h->ip_addr;
      strcpy(my_ipaddr, (char *)Sock_ntop_host(sa, sizeof(*sa)));
      my_hostname[0] = '\0';
      ip_address_to_hostname(my_ipaddr, my_hostname);
      INFO("My IP Address: %s & hostname: %s\n", my_ipaddr, my_hostname);
      break;
    }
  }
}

int
main(int argc, char **argv) {
  assert(((api_msg*)(0))->msg == (void *)API_MSG_HDR_SZ);
  atexit(on_server_exit);

  server_setup();
  memset(&s, 0, sizeof(s));
  create_srv_dsock(&s);

  (void) signal(SIGINT, on_interrupt);
  server_loop();
  return 0;
}
