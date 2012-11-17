// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _API_H_
#define _API_H_

typedef enum request_type {
  MSG_SEND = 1,
  MSG_RECV = 2,
  MSG_RESPONSE = 3
} request_type;

// #define-s for msg_flag in api_msg
#define ROUTE_REDISCOVERY_FLG 0x1

// The message which will be sent from the API to the ODR, or the other way round
#define API_MSG_STRUCT_SZ 256
#define API_MSG_HDR_SZ (sizeof(request_type) + sizeof(char)*16 + sizeof(int)*2)
#define API_MSG_SZ (API_MSG_STRUCT_SZ - API_MSG_HDR_SZ)

typedef struct api_msg { // MSG_SEND                   | MSG_RECV
  request_type rtype;    // request_type               | <unused>
  int port;              // Destination port           | Source port
  char ip[16];           // Destination IP             | Source IP
  uint32_t msg_flag;     // 0 or ROUTE_REDISCOVERY_FLG | <unused>
  char msg[API_MSG_STRUCT_SZ - API_MSG_HDR_SZ];
} api_msg;

void msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag);
void msg_recv(int sockfd, char *src_ip, int *src_port, char *msg); 

#endif 
