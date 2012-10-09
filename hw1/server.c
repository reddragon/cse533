#include "util.h"

void
time_service_thread(int *sockfd) {
  int sockfd_v = *sockfd;
  char str[100];
  time_t ticks = 0;
  fd_set readfds;
  struct timeval timeout;
  timeout.tv_sec = TIME_SERVER_SLEEP_SEC;
  timeout.tv_usec = TIME_SERVER_SLEEP_USEC;

  while (TRUE) {
    FD_ZERO(&readfds);

    FD_SET(sockfd_v, &readfds);

    int ret = select(sockfd_v + 1, &readfds, NULL, NULL, &timeout);
    if (ret <= 0) {
      fprintf(stderr, "select returned ret: %d\n", ret);
    }

    if (FD_ISSET(sockfd_v, &readfds)) {
      // The client might have died
      char buf[100], buflen = 100;
      if (read(sockfd_v, buf, buflen) <= 0) {
        fprintf(stderr, "Seems like the client has died, errno: %d\n", errno);
        close(sockfd_v);
        return;
      }
    } else {
      ticks = time(NULL);
      sprintf(str, "%s\n", ctime(&ticks));
      if (write(sockfd_v, str, strlen(str)) <= 0) {
        fprintf(stderr, "Time write failed. errno: %d\n", errno);
        if (errno == EPIPE) {
          break;
        }
        continue;
        // err_sys("time write failed");
      }
    }
  }
  if (errno == EPIPE) {
    printf("Returning\n");
    return;
  }
  close(*sockfd);
}

void
echo_service_thread(int *sockfd) {
  struct client_info *cli = (struct client_info *) malloc(sizeof(struct client_info));
  memset(cli, 0, sizeof(struct client_info));
  cli->sockfd = *sockfd;
  char *buf = (char *) malloc(sizeof(char) * MAXLEN);
  while (TRUE) {
    // readline from client
    UINT ret = buffered_readline(cli, buf, MAXLEN);
    if (ret <= 0) {
      break;
    }

    // echo line back to client
    if (write(cli->sockfd, buf, strlen(buf)) < 0) {
      err_sys("write() failed in the echo service thread");
    }
  }

  close(*sockfd);
  fprintf(stderr, "Closed the client connection\n");
}


void
run_server(void) {
  int echo_sockfd, time_sockfd;
  if ( (echo_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    err_sys("Socket Error");
  }

  if ( (time_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    err_sys("Socket Error");
  }


  int opt = TRUE, fileflags;
  // Allow this socket to be reused for multiple connections
  if (setsockopt(echo_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0) {
    err_sys("setsockopt() error");
  }

  if (setsockopt(time_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0) {
    err_sys("setsockopt() error");
  }

  // The set of socket file descriptors we can read from
  fd_set readfds, writefds;

  struct sockaddr_in echosrv_addr, timesrv_addr;
  bzero(&echosrv_addr, sizeof(struct sockaddr_in));
  echosrv_addr.sin_family = AF_INET;
  echosrv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  echosrv_addr.sin_port = htons(ECHO_SERVICE_PORT);

  bind(echo_sockfd, (struct sockaddr *) &echosrv_addr, sizeof(echosrv_addr));
  
  if ((fileflags = fcntl(echo_sockfd, F_GETFL, 0)) == -1) {
    err_sys("Could not get fileflags");
  }
  if (fcntl(echo_sockfd, F_SETFL, fileflags | O_NONBLOCK) == -1) {
    err_sys("Could not set fileflags");
  }
  
  listen(echo_sockfd, SRV_LISTENQ);

  bzero(&timesrv_addr, sizeof(struct sockaddr_in));
  timesrv_addr.sin_family = AF_INET;
  timesrv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  timesrv_addr.sin_port = htons(TIME_SERVICE_PORT);

  bind(time_sockfd, (struct sockaddr *) &timesrv_addr, sizeof(timesrv_addr));

  if ((fileflags = fcntl(time_sockfd, F_GETFL, 0)) == -1) {
    err_sys("Could not get fileflags");
  }
  if (fcntl(time_sockfd, F_SETFL, fileflags | O_NONBLOCK) == -1) {
    err_sys("Could not set fileflags");
  }

  listen(time_sockfd, SRV_LISTENQ);

  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  while(TRUE) {
    // Clear the set of socket file descriptors
    FD_ZERO(&readfds);

    // Add the socket to the set of socket file descriptors
    FD_SET(time_sockfd, &readfds);
    FD_SET(echo_sockfd, &readfds);

    fprintf(stderr, "Waiting for a connection\n");
    int ret = select(max(echo_sockfd, time_sockfd) + 1, &readfds, NULL, NULL, &timeout);
    if (ret == EINTR) {
      continue;
    }
    if ((ret < 0)) {
      err_sys("Error in select()");
    }

    if (FD_ISSET(echo_sockfd, &readfds)) {
      fprintf(stderr, "I might have possibly received a connection for the echo service\n");
      struct sockaddr *addr = (struct sockaddr *) malloc(sizeof(struct sockaddr));
      socklen_t sock_len = sizeof(struct sockaddr);
      int new_sockfd = accept(echo_sockfd, (struct sockaddr *)addr, &sock_len);
      if (new_sockfd < 0) {
        err_sys("Could not accept socket\n");
      }
      
      if ((fileflags = fcntl(time_sockfd, F_GETFL, 0)) == -1) {
        err_sys("Could not get fileflags");
      }
      
      if (fileflags & O_NONBLOCK) {
        if (fcntl(new_sockfd, F_SETFL, fileflags ^ O_NONBLOCK) == -1) {
          err_sys("Could not set fileflags");
        }
      }

      fprintf(stderr, "Received a connection for the echo service\n");
      // FD_CLR(echo_sockfd, &readfds);
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      if (pthread_create(&tid, &attr, (void *) (&echo_service_thread), (void *) (&new_sockfd)) < 0) {
        err_sys("Error in pthread_create");
      }
      // echo_service_thread(&new_sockfd);
      assert(pthread_detach(tid));
    } else if (FD_ISSET(time_sockfd, &readfds)) {
      struct sockaddr *addr;
      socklen_t sock_len;
      int new_sockfd = accept(time_sockfd, (struct sockaddr *)addr, &sock_len);
      
      fprintf(stderr, "Received a connection for the time service\n");
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      if (pthread_create(&tid, &attr, (void *) (&time_service_thread), (void *) (&new_sockfd)) < 0) {
        err_sys("Error in pthread_create");
      }
      assert(pthread_detach(tid));
    }
  }
}


int 
main(int argc, char** argv) {
  // test_datetime_server("131.107.13.100");
  run_server();
  return 0;
}
