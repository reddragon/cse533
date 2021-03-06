// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "api.h"
#include "unp.h"
#include <unistd.h>

// TODO Think about the case that Dhruv mentioned.
int 
areq(ipaddr_n ipaddr_nw, struct hwaddr *hwaddr) {
  struct sockaddr_un servaddr;
  int sockfd, ret;
  api_msg msg, resp;
  fd_set readfds;
  size_t recv_sz;
  eth_addr_ascii resp_addr;
  struct timeval timeout;

  // First unlink, then create the temp file.
  sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sun_family = AF_LOCAL;
  strcpy(servaddr.sun_path, SRV_SUNPATH);
  
  memset(&msg, 0, sizeof(msg));
  Connect(sockfd, (SA *)&servaddr, sizeof(servaddr));
  msg.ipaddr_nw = ipaddr_nw;

  Send(sockfd, (char *)&msg, sizeof(msg), 0);

  // FIXME When we have an idea of what is a reasonable timeout
  timeout.tv_sec  = 5;
  timeout.tv_usec = 0;

  FD_ZERO(&readfds);
  FD_SET(sockfd, &readfds);

  ret = Select(sockfd + 1, &readfds, NULL, NULL, &timeout);
  if (FD_ISSET(sockfd, &readfds)) {
    VERBOSE("Received response from the ARP process.\n%s", "");  
    recv_sz = Recv(sockfd, &resp, sizeof(resp), 0);
    assert_eq(recv_sz, sizeof(resp));
    hwaddr->sll_ifindex = resp.sll_ifindex;
    hwaddr->sll_hatype  = resp.sll_hatype;
    hwaddr->sll_halen   = resp.sll_halen;
    memcpy(hwaddr->sll_addr, resp.eth_addr.addr, 
    sizeof(resp.eth_addr.addr));
    resp_addr = pp_eth(resp.eth_addr.addr);
    VERBOSE("Received address: %s.\n", resp_addr.addr);
    close(sockfd);
    return 0;
  } else {
    INFO("Timed out while waiting for the ARP process. ret = %d\n", ret);
    close(sockfd);
  }
  return -1;
}
