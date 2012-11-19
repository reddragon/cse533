// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "api.h"

int
msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int msg_flag) {
  api_msg m;
  struct sockaddr_un serv_addr;

  bzero(&m, sizeof(api_msg));
  m.rtype = MSG_SEND;
  m.port = dst_port;
  strcpy(m.ip, dst_ip);
  m.msg_flag = msg_flag;
  strncpy(m.msg, msg, sizeof(api_msg) - API_MSG_HDR_SZ - 1);
  
  strcpy(serv_addr.sun_path, ODR_DGPATH);
  serv_addr.sun_family = AF_LOCAL;
  // Send the newly marshalled API message to the ODR.
  // The ODR will take care of the rest
  return sendto(sockfd, (char *) &m, sizeof(api_msg), 0, (SA *)&serv_addr, sizeof(serv_addr));
}

int
msg_connect_to_odr(int sockfd) {
  // We send a blank message letting ODR know of our presence.
  api_msg m;
  struct sockaddr_un serv_addr;

  bzero(&m, sizeof(api_msg));
  m.rtype = MSG_CONNECT;

  strcpy(serv_addr.sun_path, ODR_DGPATH);
  serv_addr.sun_family = AF_LOCAL;

  // Just send the header of the API Message
  return sendto(sockfd, (char *) &m, API_MSG_HDR_SZ, 0, (SA *)&serv_addr, sizeof(serv_addr));
}

int
msg_recv(int sockfd, char *src_ip, int *src_port, char *msg) {
  api_msg r;
  int ret;
  struct sockaddr_un serv_addr;

  // The message which will have the response
  VERBOSE("Waiting for a Recv\n%s", "");
  ret = recv(sockfd, (char *) &r, sizeof(api_msg), 0);
  if (ret < 0) {
    return ret;
  }
  assert(ret == sizeof(api_msg));
  VERBOSE("Came out of a Recv\n%s", "");
  VERBOSE("Message: %s\n", r.msg);
  *src_port = r.port;
  strncpy(src_ip, r.ip, 20);
  memcpy(msg, r.msg, sizeof(r.msg));
  return ret;
}
