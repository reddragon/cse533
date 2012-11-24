// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _API_H_
#define _API_H_

typedef enum request_type {
  MSG_SEND = 1,
  MSG_RECV = 2,
  MSG_RESPONSE = 3,
  MSG_CONNECT = 4
} request_type;

// #define-s for msg_flag in api_msg
#define ROUTE_REDISCOVERY_FLG    0x1
#define RREP_ALREADY_SENT_FLG   0x10
#define RREQ_ALREADY_SENT_FLG  0x100

// The message which will be sent from the API to the ODR, or the other way round
typedef struct api_msg { // MSG_SEND                   | MSG_RECV
  request_type rtype;    // request_type               | <unused>
  int port;              // Destination port           | Source port
  char ip[16];           // Destination IP             | Source IP
  uint32_t msg_flag;     // 0 or ROUTE_REDISCOVERY_FLG | <unused>
  char msg[API_MSG_SZ];
} api_msg;

#define API_MSG_HDR_SZ ((int)(((api_msg*)0)->msg))

int msg_connect_to_odr(int sockfd);
int msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag);
int msg_recv(int sockfd, char *src_ip, int *src_port, char *msg);

#endif 
