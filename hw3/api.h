#ifndef _API_H_
#define _API_H_

// The message which will be sent from the API to the ODR, or the other way round
#define API_MSG_HDR_SZ (sizeof(char)*4 + sizeof(short))
typedef struct api_msg {
  char dst_ip[4];
  short dst_port;
  char msg[512 - API_MSG_HDR_SZ];
} outgoing_msg;

void msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag);
void msg_recv(int sockfd, char *src_ip, int *src_port, char *msg); 

#endif 
