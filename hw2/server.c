#include "utils.h"

void
bind_udp(struct server_args *sargs, int *sockfd_arr, int *sock_arr_len) {  
  struct ifi_info *ifi, *ifi_head;
  int sockfd;
  const int yes = 1;
  struct sockaddr_in *sa;

  // TODO What is doaliases doing?
  ifi_head = Get_ifi_info_plus(AF_INET, 1);
  
  *sock_arr_len = 0;
  for (ifi = ifi_head; ifi != NULL; ifi = ifi->ifi_next) {
    sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sa = (struct sockaddr_in *) ifi->ifi_addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(sargs->serv_portno);
    Bind(sockfd, (SA *) sa, sizeof(*sa));
    sockfd_arr[*sock_arr_len] = sockfd;
    *sock_arr_len = *sock_arr_len + 1;
    assert(ifi->ifi_ntmaddr != NULL);
    struct sockaddr* sn_addr = get_subnet_addr((SA *)sa, (SA *)ifi->ifi_ntmaddr);
    printf("Bound socket on\n\taddress: %s\n\tnetwork mask: %s\n\tsubnet address: %s\n", 
      sa_data_str((SA *)sa), 
      sa_data_str((SA *)ifi->ifi_ntmaddr), 
      sa_data_str(get_subnet_addr((SA *)sa, (SA *)ifi->ifi_ntmaddr)));
  }
}

int main(int argc, char **argv) {
  const char *sargs_file = SARGS_FILE;
  struct server_args *sargs = MALLOC(struct server_args);
  int sockfd_arr[MAXSOCKS], sockfd_arr_len, i;
  read_sargs(sargs_file, sargs);
  bind_udp(sargs, sockfd_arr, &sockfd_arr_len);
  
  fd_set readfds;
  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  int mx_sockfd = 0;
  while (1) {
    FD_ZERO(&readfds);
    for (i = 0; i < sockfd_arr_len; i++) {
      FD_SET(sockfd_arr[i], &readfds);
      mx_sockfd = (mx_sockfd < sockfd_arr[i]) ? sockfd_arr[i] : mx_sockfd;
    }
    Select(mx_sockfd + 1, &readfds, NULL, NULL, &timeout);

    for (i = 0; i < sockfd_arr_len; i++) {
      if (FD_ISSET(sockfd_arr[i], &readfds)) {
        printf("Read from %d\n", sockfd_arr[i]);
      }
    }
  }
  return 0;
}
