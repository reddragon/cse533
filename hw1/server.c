#include "util.h"

void
time_service_thread(int *sockfd) {
  char str[100];
  time_t ticks = 0;
  while (TRUE) {
    // Replace by the daytime
    ticks = time(NULL);
    sprintf(str, "%s\n", ctime(&ticks));
    if (write(*sockfd, str, strlen(str)) < 0) {
      err_sys("time write failed");
    }
    sleep(TIME_SERVER_SLEEP);
  }
}

void
echo_service_thread(int *sockfd) {
  struct client_info *cli = (struct client_info *) malloc(sizeof(struct client_info));
  memset(cli, 0, sizeof(struct client_info));
  cli->sockfd = *sockfd;
  char *buf = (char *) malloc(sizeof(char) * MAXLEN);
  while (TRUE) {
    // readline from client
    fprintf(stderr, "Starting readline call\n");
    UINT ret = buffered_readline(cli, buf, MAXLEN);
    if (ret <= 0) {
      break;
    }
    
    // echo line back to client
    if (write(cli->sockfd, buf, strlen(buf)) < 0) {
      err_sys("echo write failed");
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


  int opt = TRUE;
  // Allow this socket to be reused for multiple connections
  if (setsockopt(echo_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0) {
    err_sys("setsockopt() error");
  }

  if (setsockopt(time_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt)) < 0) {
    err_sys("setsockopt() error");
  }

  // The set of socket file descriptors
  fd_set readfds;
  
  struct sockaddr_in echosrv_addr, timesrv_addr;
  bzero(&echosrv_addr, sizeof(struct sockaddr_in));
  echosrv_addr.sin_family = AF_INET;
  echosrv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  echosrv_addr.sin_port = htons(ECHO_SERVICE_PORT);

  bind(echo_sockfd, (struct sockaddr *) &echosrv_addr, sizeof(echosrv_addr));
  listen(echo_sockfd, SRV_LISTENQ);

  bzero(&timesrv_addr, sizeof(struct sockaddr_in));
  timesrv_addr.sin_family = AF_INET;
  timesrv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  timesrv_addr.sin_port = htons(TIME_SERVICE_PORT);

  bind(time_sockfd, (struct sockaddr *) &timesrv_addr, sizeof(timesrv_addr));
  listen(time_sockfd, SRV_LISTENQ);

  while(TRUE) {
    // Clear the set of socket file descriptors
    FD_ZERO(&readfds);

    // Add the socket to the set of socket file descriptors
    FD_SET(echo_sockfd, &readfds);
    FD_SET(time_sockfd, &readfds);

    fprintf(stderr, "Waiting for a connection\n");
    int ret = select(max(echo_sockfd, time_sockfd) + 1, &readfds, NULL, NULL, NULL);
    if ((ret < 0)) {
      err_sys("Errorn in select()");
    }

    if (FD_ISSET(echo_sockfd, &readfds)) {
      fprintf(stderr, "I might have possibly received a connection for the echo service\n");
      struct sockaddr *addr;
      socklen_t sock_len;
      int new_sockfd = accept(echo_sockfd, (struct sockaddr *)addr, &sock_len);
      
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      if (pthread_create(&tid, &attr, (void *) (&echo_service_thread), (void *) (&new_sockfd)) < 0) {
        err_sys("Error in pthread_create");
      }
      pthread_detach(tid);
    } else if (FD_ISSET(time_sockfd, &readfds)) {
      fprintf(stderr, "I might have possibly received a connection for the time service\n");
      struct sockaddr *addr;
      socklen_t sock_len;
      int new_sockfd = accept(time_sockfd, (struct sockaddr *)addr, &sock_len);
      
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      if (pthread_create(&tid, &attr, (void *) (&time_service_thread), (void *) (&new_sockfd)) < 0) {
        err_sys("Error in pthread_create");
      }
      pthread_detach(tid);
    }
  }
}


int 
main(int argc, char** argv) {
	// test_datetime_server("131.107.13.100");
  run_server();
  return 0;
}
