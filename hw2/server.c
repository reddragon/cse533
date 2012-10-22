// -*- mode: c; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "fdset.h"

void
get_conn(struct sockaddr *cli_sa, struct server_conn *conn) {
  // TODO
  // Check if this function is fine
  struct ifi_info *ifi_head = Get_ifi_info_plus(AF_INET, 0), *ifi;
  struct sockaddr* sa = NULL;
  int cli_portno = ((struct sockaddr_in *)cli_sa)->sin_port;
  char *cli_ip_addr = sa_data_str(cli_sa);

  UINT longest_match_len = 0;
  // Find if the server is local to the client
  conn->is_local = FALSE;
  for (ifi = ifi_head; ifi != NULL; ifi = ifi->ifi_next) {
    char *if_addr_str = Sock_ntop(ifi->ifi_addr, sizeof(SA));
    
    // printf("Address: %s NTM: %s NTM Len: %d\n", if_addr_str, sa_data_str(ifi->ifi_ntmaddr), get_ntm_len(ifi->ifi_ntmaddr));

    // If we found the same IP being used by one of the interfaces,
    // then we simply say that the server is local, marshal the
    // client connection structure properly, and return.
    if (!strcmp(if_addr_str, cli_ip_addr)) {
      conn->is_local = TRUE;
      conn->cli_sa = inet_pton_sa("127.0.0.1", cli_portno);
      conn->serv_sa = inet_pton_sa("127.0.0.1", 0);
      break;
    }
    
    // Now check if (server's IP addr & server network mask) is the
    // same as (client's IP addr & client network mask). If yes,
    // store it. (Only if the prefix match is longer than any
    // previous prefix match found, thus far.
    struct sockaddr *cli_snaddr = get_subnet_addr(cli_sa, ifi->ifi_ntmaddr);
    char *cli_snaddr_str = sa_data_str(cli_snaddr);
    struct sockaddr *serv_snaddr = get_subnet_addr(ifi->ifi_addr, ifi->ifi_ntmaddr);
    char *serv_snaddr_str = sa_data_str(serv_snaddr);
    UINT ntm_len = get_ntm_len(ifi->ifi_ntmaddr);
    
    // printf("ntm: %s serv_snaddr: %s, cli_snaddr: %s\n", sa_data_str(ifi->ifi_ntmaddr), serv_snaddr_str, cli_snaddr_str);
    if (!strcmp(serv_snaddr_str, cli_snaddr_str) && ntm_len > longest_match_len) {
      longest_match_len = ntm_len;
      conn->is_local = TRUE;
      conn->cli_sa = inet_pton_sa("127.0.0.1", cli_portno);
      conn->serv_sa = inet_pton_sa("127.0.0.1", 0);
      break;
    }
  }
  
  if (sa == NULL) {
    conn->is_local = FALSE;
    // TODO
    // The first address might be a loopback address. Can we choose it like that?
    conn->serv_sa = ifi_head->ifi_addr;
    conn->cli_sa = cli_sa;
  }
}

// Most of the heavy lifting happens here
void
ftp(int old_sockfd, struct sockaddr* cli_sa, const char *file_name) {
  struct server_conn conn;
  get_conn(cli_sa, &conn);
  printf("Client is %s\nIPServer: %s\nIPClient: %s\n", 
    (conn.is_local ? "Local" : "Not Local"),
    sa_data_str(conn.serv_sa),
    sa_data_str(conn.cli_sa));
  int sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
  Bind(sockfd, conn.serv_sa, sizeof(SA));
  struct sockaddr_in sin;
  UINT addrlen = sizeof(SA);
  Getsockname(sockfd, (SA *)&sin, &addrlen);
  printf("Client: %s\n", sa_data_str(conn.cli_sa));
  printf("Server's ephemeral Port Number: %d\n", sin.sin_port);
  Connect(sockfd, conn.cli_sa, sizeof(SA));
  // TODO
  // Finish the ARQ part. This is not reliable
  char portno_str[20];
  sprintf(portno_str, "%d", sin.sin_port);
  Sendto(sockfd, (void *)portno_str, strlen(portno_str), 
    MSG_DONTROUTE, conn.cli_sa, sizeof(SA)); 
  close(sockfd);
}


void
bind_udp(struct server_args *sargs, vector *v) {
  struct ifi_info *ifi, *ifi_head;
  int sockfd;
  const int yes = 1;
  struct sockaddr_in *sa;

  // TODO What is doaliases doing?
  ifi_head = Get_ifi_info_plus(AF_INET, 1);
  
  for (ifi = ifi_head; ifi != NULL; ifi = ifi->ifi_next) {
    assert(ifi->ifi_ntmaddr != NULL);

    sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    Setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sa = (struct sockaddr_in *) ifi->ifi_addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons(sargs->serv_portno);

    Bind(sockfd, (SA *) sa, sizeof(*sa));

    vector_push_back(v, &sockfd);

    struct sockaddr* sn_addr = get_subnet_addr((SA *)sa, (SA *)ifi->ifi_ntmaddr);
    printf("Bound socket on\n\taddress: %s\n\tnetwork mask: %s\n\tsubnet address: %s\n",
           sa_data_str((SA *)sa),
           sa_data_str((SA *)ifi->ifi_ntmaddr),
           sa_data_str(sn_addr));
  }
}

int main(int argc, char **argv) {
  const char *sargs_file = SARGS_FILE;
  struct server_args sargs;
  int i;
  vector socklist;

  vector_init(&socklist, sizeof(int));
  read_sargs(sargs_file, &sargs);
  bind_udp(&sargs, &socklist);

  fdset fds;
  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  while (1) {
    fdset_init(&fds);
    fdset_add_all(&fds, &fds.rfds, &socklist);
    fdset_add_all(&fds, &fds.exfds, &socklist);

    Select(fds.max_fd + 1, &fds.rfds, NULL, &fds.exfds, &timeout);
    // TODO: Handle EINTR.

    for (i = 0; i < vector_size(&socklist); i++) {
      int fd = *(int*)vector_at(&socklist, i);

      // TODO: Check exfds as well.
      if (FD_ISSET(fd, &fds.rfds)) {
        printf("There is a disturbance in the force at '%d'\n", fd);
        char file_name[1000];
        struct sockaddr sa;
        struct sockaddr_in *si = (struct sockaddr_in *) &sa;
        socklen_t sa_sz;

        // TODO: Fixme - handle return value and don't exit.
        Recvfrom(fd, (void *) file_name, 1000, 0, &sa, &sa_sz);
        printf("Request for file: %s from IP Address: %s and Port: %u\n", 
               file_name, sa_data_str(&sa), (si->sin_port));

        int pid = fork();
        if (pid < 0) {
          // err_sys("Error while doing fork()");
          perror("fork");
          // Exit process.
          exit(1);
        }
        if (pid == 0) {
          // Child: Close all the sockets except the one that the
          // child owns.
          int j;
          for (j = 0; j < vector_size(&socklist); j++) {
            int sockfd = *(int*)vector_at(&socklist, j);
            if (sockfd != i) {
              close(sockfd);
            }
          }
          ftp(fd, &sa, file_name);
          printf("Child process exiting\n");
          exit(0);
        }
      }
    }
  }
  return 0;
}
