// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "api.h"
#include "unp.h"
#include <unistd.h>

// TODO Think about the case that Dhruv mentioned.
int 
areq(ipaddr_n ipaddr_nw, struct hwaddr *hwaddr) {
  struct sockaddr_un servaddr, cliaddr;
  char *tmp_file;
  int sockfd, ret;
  api_msg msg, resp;
  fd_set readfds;
  size_t recv_sz;
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
  msg.ipaddr_nw = ipaddr_nw;

  Send(sockfd, (char *)&msg, sizeof(msg), 0);

  // FIXME When we have an idea of what is a reasonable timeout
  timeout.tv_sec  = 10;
  timeout.tv_usec = 0;
  
  FD_ZERO(&readfds);
  FD_SET(sockfd, &readfds);
  
  ret = Select(sockfd + 1, &readfds, NULL, NULL, &timeout);
  if (FD_ISSET(sockfd, &readfds)) {
    VERBOSE("Received response from the ARP process.\n%s", "");  
    recv_sz = Recv(sockfd, &resp, sizeof(resp), 0);
    assert(recv_sz == sizeof(resp));  
    hwaddr->sll_ifindex = resp.sll_ifindex;
    hwaddr->sll_hatype  = resp.sll_hatype;
    hwaddr->sll_halen   = resp.sll_halen;
    memcpy(hwaddr->sll_addr, resp.eth_addr.addr, 
    sizeof(resp.eth_addr.addr));
    return 0;
  } else {
    INFO("Timed out while waiting for the ARP process. ret = %d\n", ret);
  }
  return 1;
}
