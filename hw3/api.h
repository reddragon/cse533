#ifndef _API_H_
#define _API_H_

typedef enum request_type {
  MSG_SEND = 1,
  MSG_RECV = 2
} request_type;

// #define-s for msg_flag in api_msg
#define ROUTE_REDISCOVERY_FLG 0x1

// The message which will be sent from the API to the ODR, or the other way round
#define API_MSG_SZ 256
#define API_MSG_HDR_SZ (sizeof(request_type) + sizeof(char)*16 + sizeof(int)*2)
typedef struct api_msg {
  request_type rtype;
  int port;
  char ip[16];
  int msg_flag;
  char msg[API_MSG_SZ - API_MSG_HDR_SZ];
} api_msg;

void msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag);
void msg_recv(int sockfd, char *src_ip, int *src_port, char *msg); 

#endif 
