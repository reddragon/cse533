#include <stdio.h>
#include "util.h"

int lfd;
FILE *lfp;

#define MAXMSGBUF 1000

int
send_to_parent(const char *s) {
  return write(lfd, s, strlen(s));
}

void
err(char *s) {
  char *str = get_err_str(s);
  if (send_to_parent(str) <= 0) {
    fprintf(stderr, "Sending message \"%s\" to parent process failed\n", str);   
  }
  close(lfd);
  err_sys((char *)s);
}

void 
run_echo_client(char *addr) {
  int sockfd;
  struct sockaddr_in servaddr;

  // Create a socket of type Internet (AF_INET) stream (SOCK_STREAM)
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    err("Could not create socket");
  }

  // Zeroes out the servaddr structure
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(ECHO_SERVICE_PORT); 

  // Presentation -> Notation. Convert IP address to binary form, and
  // save it in servaddr.sin_addr
  if (inet_pton(AF_INET, addr, &servaddr.sin_addr) <= 0) {
    err("Could not set server address in servaddr");
  }

  // The connect function, when applied on a TCP socket, establishes
  // a TCP connection with the server, using the sock
  int ret;
  if ((ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))) < 0) {
    err("Error in connect() while trying to connect to the echo server.");
  }

  struct client_info *cli = (struct client_info *) malloc(sizeof(struct client_info));
  memset(cli, 0, sizeof(struct client_info));
  cli->sockfd = sockfd;
  UINT scanf_ret;
  while (TRUE) {
    char str[MAXLEN], newLineChar;
    size_t str_sz = MAXLEN;
    if ((scanf_ret = scanf("%[^\n]", str)) == 0) {
      continue;
    }
    if (scanf_ret == EOF) {
      send_to_parent("Received a ^D in the input");
      break;
    }
    newLineChar = getchar();
    int wret = 0;
    if ((wret = write(cli->sockfd, str, strlen(str))) <= 0) {
      err("Could not write to socket");
    }
    printf("wret: %d\n", wret);
    char rstr[MAXLEN];
    if (buffered_readline(cli, rstr, MAXLEN) <= 0) {
      err("Could not read a line from the server's end");
    }
    fprintf(stderr, "Server Responded: %s\n", rstr);
  }
  close(sockfd);
  close(lfd);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    err_sys("Usage: ./echocli <Server IP Address> <Log File Descriptor>");
  }
  sscanf(argv[2], "%d", &lfd);
  run_echo_client(argv[1]);
  return 0;
}
