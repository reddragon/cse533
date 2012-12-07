// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "api.h"
#include "unp.h"
#include <unistd.h>

// TODO Think about the case that Dhruv mentioned.
int 
areq(ipaddr_ascii ipaddr, socklen_t slen, struct hwaddr *hwaddr) {
  struct sockaddr_un servaddr, cliaddr;
  char *tmp_file;
  int sockfd;
  api_msg msg;
  // fdset fds;
  struct timeval timeout;

  // First unlink, then create the temp file.
  unlink(tmp_file);
  tmp_file = create_tmp_file();

  sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
  bzero(&cliaddr, sizeof(cliaddr));
  cliaddr.sun_family = AF_LOCAL;
  strcpy(cliaddr.sun_path, tmp_file);
  
  Bind(sockfd, (SA *)&cliaddr, sizeof(cliaddr));

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sun_family = AF_LOCAL;
  strcpy(servaddr.sun_path, SRV_SUNPATH);

  Connect(sockfd, (SA *)&servaddr, sizeof(servaddr));
  inet_pton(AF_INET, ipaddr.addr, &msg.ipaddr_nw);  
  
  Sendto(sockfd, (char *)&msg, sizeof(msg), 0, (SA *)&servaddr, sizeof(servaddr));

  // FIXME When we have an idea of what is a reasonable timeout
  timeout.tv_sec  = 10;
  timeout.tv_usec = 0;
  

}
