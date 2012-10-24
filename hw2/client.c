#include <stdio.h>
#include "utils.h"

void
get_conn(struct client_args *cargs, struct client_conn *conn) {
  // TODO
  // Check if this function is fine
  struct ifi_info *ifi_head = Get_ifi_info_plus(AF_INET, 0), *ifi;
  struct sockaddr* sa = NULL, *serv_sa = inet_pton_sa((const char *)cargs->ip_addr, cargs->serv_portno);
  printf("Client Interfaces:\n");
  print_ifi_info(ifi_head);
  printf("\n");

  UINT longest_match_len = 0;
  // Find if the server is local to the client
  conn->is_local = FALSE;
  for (ifi = ifi_head; ifi != NULL; ifi = ifi->ifi_next) {
    char *if_addr_str = Sock_ntop(ifi->ifi_addr, sizeof(SA));
    
    // printf("Address: %s NTM: %s NTM Len: %d\n", if_addr_str, sa_data_str(ifi->ifi_ntmaddr), get_ntm_len(ifi->ifi_ntmaddr));

    // If we found the same IP being used by one of the interfaces,
    // then we simply say that the server is local, marshal the
    // client connection structure properly, and return.
    if (!strcmp(if_addr_str, cargs->ip_addr)) {
      // printf("Server address: %s, is local\n", cargs->ip_addr);
      conn->is_local = TRUE;
      conn->serv_sa = inet_pton_sa("127.0.0.1", cargs->serv_portno);
      conn->cli_sa = inet_pton_sa("127.0.0.1", 0);
      break;
    }
    
    // Now check if (server's IP addr & server network mask) is the
    // same as (client's IP addr & client network mask). If yes,
    // store it. (Only if the prefix match is longer than any
    // previous prefix match found, thus far.
    struct sockaddr *serv_snaddr = get_subnet_addr(serv_sa, ifi->ifi_ntmaddr);
    char *serv_snaddr_str = sa_data_str(serv_snaddr);
    struct sockaddr *cli_snaddr = get_subnet_addr(ifi->ifi_addr, ifi->ifi_ntmaddr);
    char *cli_snaddr_str = sa_data_str(cli_snaddr);
    UINT ntm_len = get_ntm_len(ifi->ifi_ntmaddr);
    
    // printf("ntm: %s serv_snaddr: %s, cli_snaddr: %s\n", sa_data_str(ifi->ifi_ntmaddr), serv_snaddr_str, cli_snaddr_str);
    if (!strcmp(serv_snaddr_str, cli_snaddr_str) && ntm_len > longest_match_len) {
      longest_match_len = ntm_len;
      conn->is_local = TRUE;
      conn->serv_sa = inet_pton_sa("127.0.0.1", cargs->serv_portno);
      conn->cli_sa = inet_pton_sa("127.0.0.1", 0);
      break;
    }
  }
  
  if (sa == NULL) {
    conn->is_local = FALSE;
    // TODO
    // The first address might be a loopback address. Can we choose it like that?
    conn->cli_sa = ifi_head->ifi_addr;
    conn->serv_sa = inet_pton_sa((const char *)cargs->ip_addr, cargs->serv_portno);
  }
}

// Connect to the server, and send the first datagram
void
start_tx(struct client_args *cargs, struct client_conn *conn) {
  int sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

  // Bind to port 0
  Bind(sockfd, conn->cli_sa, sizeof(SA));

  struct sockaddr_in sin;
  UINT addrlen = sizeof(SA);

  // Fetch port number at which kernel bound this socket.
  Getsockname(sockfd, (SA *)&sin, &addrlen);
  int cliport = ntohs(sin.sin_port);
  printf("Client's ephemeral Port Number: %d\n", cliport);

  // Connect to the server.
  Connect(sockfd, conn->serv_sa, sizeof(SA));

  // TODO
  // Do we need getpeername here?
  
  // Sending the file name to the server
  // Q. Do we need to pass the conn->serv_sa here?

  packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.ack = 0;
  pkt.seq = 0;
  pkt.flags = FLAG_SYN;
  pkt.datalen = strlen(cargs->file_name);
  strcpy(pkt.data, cargs->file_name);

  printf("Sending %d bytes of data to the server\n", sizeof(pkt));
  Sendto(sockfd, (void*)&pkt, sizeof(pkt), MSG_DONTROUTE, // The DONTROUTE might be wrong.
         conn->serv_sa, sizeof(SA));

  int portno;
  struct sockaddr sa;
  struct sockaddr_in *si = (struct sockaddr_in *) &sa;
  socklen_t sa_sz = sizeof(sa);

  Recvfrom(sockfd, (void*)&pkt, sizeof(pkt), 0, &sa, &sa_sz);

  pkt.data[pkt.datalen] = '\0';
  sscanf(pkt.data, "%d", &portno);
  const char *serverIP = sa_data_str(&sa);

  printf("Server endpoints {1} [%s:%d] & {2} [%s:%d]\n", serverIP, ntohs(si->sin_port), serverIP, portno);

  // Disconnect port association.
  sa.sa_family = AF_UNSPEC;
  Connect(sockfd, &sa, sizeof(SA));

  // Bind to the port we were originally bound to, and connect this
  // socket to the new port number that the server sent us.
  struct sockaddr_in cli_si = *(struct sockaddr_in*)conn->cli_sa;
  cli_si.sin_port = htons(cliport);
  Bind(sockfd, (struct sockaddr*)&cli_si, sizeof(SA));
  sa = *(conn->serv_sa);
  si->sin_port = htons(portno);
  Connect(sockfd, &sa, sizeof(SA));

  // Receive data from the socket till a packet with the FLAG_FIN flag
  // is received. Open the file for writing.

  char file_name[300];
  sprintf(file_name, "%s.out", "test");

  FILE *pf = fopen(file_name, "w");
  assert(pf);
  while (1) {
      fprintf(stdout, "Waiting on Recv...\n");
      int r = recv(sockfd, (void*)&pkt, sizeof(pkt), 0);
      fprintf(stdout, "recv(2) returned with exit code: %d\n", r);

      if (r < 0 && errno == EINTR) {
          continue;
      }
      if (r < 0) {
          perror("recv");
          break;
      }
      if (r == 0) {
          fprintf(stdout, "End of file while recv(2)ing file\n");
          break;
      }
      // , &sa, &sa_sz);
      fwrite(pkt.data, pkt.datalen, 1, pf);
      if (pkt.flags & FLAG_FIN) {
          break;
      }
  }
  fclose(pf);
}

int main(int argc, char **argv) {
  assert(argc == 1);
  const char *cargs_file = CARGS_FILE;
  struct client_args *cargs = (struct client_args *)
    malloc(sizeof(struct client_args));
  if (read_cargs((const char *)cargs_file, cargs)) {
    exit(1);
  }
  
  struct client_conn conn;
  get_conn(cargs, &conn);
  printf("Server is %s\nIPServer: %s\nIPClient: %s\n", 
          (conn.is_local ? "Local" : "Not Local"),
          sa_data_str(conn.serv_sa),
          sa_data_str(conn.cli_sa));
  // printf("IPServer: %s\n", Sock_ntop(sa, sizeof(SA)));
  start_tx(cargs, &conn);
  return 0;
}
