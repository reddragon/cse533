#include <stdio.h>
#include "util.h"

void 
test_time_server(char *addr) {
	int sockfd;
	struct sockaddr_in servaddr;
	
	// Create a socket of type Internet (AF_INET) stream (SOCK_STREAM)
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		err_sys("Could not create socket");
	}

	// Zeroes out the servaddr structure
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(TIME_SERVICE_PORT); 
	
	// Presentation -> Notation. Convert IP address to binary form, and
	// save it in servaddr.sin_addr
	if (inet_pton(AF_INET, addr, &servaddr.sin_addr) <= 0) {
		err_sys("Could not set server address in servaddr");
	}
	
	// The connect function, when applied on a TCP socket, establishes
	// a TCP connection with the server, using the sock
	int ret;
	if ((ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))) < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		err_sys("connect error");
	}
  
  struct client_info *cli = (struct client_info *) malloc(sizeof(struct client_info));
  memset(cli, 0, sizeof(struct client_info));
  cli->sockfd = sockfd;
  while (TRUE) {
    char rstr[MAXLEN];
    if (read(cli->sockfd, rstr, MAXLEN) < 0) {
      err_sys("read returned with < 0 chars");
    }
    fprintf(stderr, "Server: %s", rstr);
  }
  close(sockfd);
}

int main(int argc, char **argv) {
	if (argc != 2) {
    // TODO Fill this up
    err_sys("Usage: ./timecli <Server IP Address>");
  }
  test_time_server(argv[1]);
  return 0;
}

