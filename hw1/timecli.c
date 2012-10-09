#include <stdio.h>
#include "util.h"

int lfd;

int
send_to_parent(char *s) {
  return write(lfd, s, strlen(s));
}

void
err(char *s) {
  char str[MAXMSGLEN];
  sprintf(str, "%s errno: %d (%s)\n", s, errno, (errno ? strerror(errno) : ""));
  if (send_to_parent(str) <= 0) {
    fprintf(stderr, "Sending message \"%s\" to parent process failed\n", str);   
  }
  close(lfd);
  err_sys((char *)s);
}

void 
run_time_client(char *addr) {
  int sockfd;
  struct sockaddr_in servaddr;

  // Create a socket of type Internet (AF_INET) stream (SOCK_STREAM)
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    err("Could not create socket for time service");
  }
  send_to_parent("Created the timecli socket.");

  // Zeroes out the servaddr structure
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(TIME_SERVICE_PORT); 

  // Presentation -> Notation. Convert IP address to binary form, and
  // save it in servaddr.sin_addr
  if (inet_pton(AF_INET, addr, &servaddr.sin_addr) <= 0) {
    err("Could not set server address in servaddr for the time service.");
  }

  send_to_parent("Now trying to connect with the time server.");
  // The connect function, when applied on a TCP socket, establishes
  // a TCP connection with the server, using the sock
  int ret;
  if ((ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))) < 0) {
    err("Error in connect() while trying to connect to the time server.");
  }

  send_to_parent("Connected to the time server! Now trying to read the time.");
  struct client_info *cli = (struct client_info *) malloc(sizeof(struct client_info));
  memset(cli, 0, sizeof(struct client_info));
  cli->sockfd = sockfd;
  while (TRUE) {
    char rstr[MAXLEN];
    fprintf(stderr, "Waiting for the server to respond.\n");
    if (read(cli->sockfd, rstr, MAXLEN) <= 0) {
      if (errno == EINTR) {
        send_to_parent("Received an EINTR\n");
      }
      err("Read returned with <= 0 chars. Server possibly disconnected.");
      break;
    }
    fprintf(stderr, "Server: %s", rstr);
  }
  close(sockfd);
}

int main(int argc, char **argv) {
  lfd = 0;
  if (argc != 3) {
    // TODO Fill this up
    err_sys("Usage: ./timecli <Server IP Address> <Log File Descriptor>");
  }
  sscanf(argv[2], "%d", &lfd);
  run_time_client(argv[1]);
  return 0;
}

