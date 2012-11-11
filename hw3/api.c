#include "utils.h"
#include "api.h"

void 
msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag) {
  // TODO Fill this up
  // I think we can use a packet struct to communicate with the ODR service
  // Filler code for now
}

void msg_recv(int sockfd, char *src_ip, int *src_port, char *msg) {
  // TODO Fill this up
}
