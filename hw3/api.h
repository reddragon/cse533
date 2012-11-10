#ifndef _API_H_
#define _API_H_

void msg_send(int sockfd, char *dst_ip, int dst_port, char *msg, int flag);
void msg_recv(int sockfd, char *src_ip, int *src_port, char *msg); 

#endif 
