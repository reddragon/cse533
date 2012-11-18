// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"

void 
msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int msg_flag) {
  api_msg m;
  bzero(&m, sizeof(api_msg));
  m.rtype = MSG_SEND;
  m.port = dst_port;
  strcpy(m.ip, dst_ip);
  m.msg_flag = msg_flag;
  strncpy(m.msg, msg, sizeof(api_msg) - API_MSG_HDR_SZ - 1);
  
  struct sockaddr_un serv_addr;
  strcpy(serv_addr.sun_path, SRV_DGPATH);
  serv_addr.sun_family = AF_LOCAL;
  // Send the newly marshalled API message to the ODR.
  // The ODR will take care of the rest
  Sendto(sockfd, (char *) &m, sizeof(api_msg), 0, (SA *)&serv_addr, sizeof(serv_addr));
}

void 
msg_recv(int sockfd, char *src_ip, int *src_port, char *msg) {
  // In this, we need to send one API message, and then
  // receive another
  api_msg m, r;
  bzero(&m, sizeof(api_msg));
  m.rtype = MSG_RECV;
  
  struct sockaddr_un serv_addr;
  strcpy(serv_addr.sun_path, SRV_DGPATH);
  serv_addr.sun_family = AF_LOCAL;

  // Just send the header of the API Message
  Sendto(sockfd, (char *) &m, API_MSG_HDR_SZ, 0, (SA *)&serv_addr, sizeof(serv_addr));
  
  // TODO Put a timeout here
  // The message which will have the response
  VERBOSE("Waiting for a Recv\n%s", "");
  Recv(sockfd, (char *) &r, sizeof(api_msg), 0);
  VERBOSE("Came out of a Recv\n%s", "");
  VERBOSE("Message: %s\n", r.msg);
  *src_port = r.port;
  strncpy(src_ip, r.ip, 20);
  memcpy(msg, r.msg, sizeof(r.msg));
}
