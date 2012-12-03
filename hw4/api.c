#include "api.h"

int 
areq(ipaddr_a ipaddr, socklen_t slen, struct hwaddr *hwaddr) {
  struct sockaddr_un servaddr, cliaddr;
  char *tmp_file, *;
  int sockfd;
  api_msg msg;
  // fdset fds;
  struct timeval timeout;

  tmp_file = create_tmp_file();
  unlink(tmp_file);
  sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
  bzero(&cliaddr, sizeof(cliaddr));
  cliaddr.sun_family = AF_LOCAL;
  strcpy(cliaddr.sun_path, tmp_file);
  
  Bind(sockfd, (SA *)&cliaddr, sizeof(cliaddr));

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sun_family = AF_LOCAL;
  strcpy(servaddr.sun_path, SRV_SUNPATH);

  Connect(sockfd, (SA *)&servaddr, sizeof(servaddr));
  msg.ipaddr = ipaddr;
  
  Sendto(sockfd, (char *)&api_msg, sizeof(api_msg), 0, (SA *)&serv_addr, sizeof(serv_addr));
  
  // FIXME When we have an idea of what is a reasonable timeout
  timeout.tv_sec  = 10;
  timeout.tv_usec = 0;
  /*
  fdset_init(&fds, timeout, NULL);

  fdset_add(&fds, &fds.rev,  sockfd, &c.sockfd, on_recv);
  fdset_add(&fds, &fds.exev, sockfd, &c.sockfd, on_error);
  */

}
