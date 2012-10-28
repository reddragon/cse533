#include <stdio.h>
#include "utils.h"
#include "rwindow.h"
#include "fdset.h"

client_args *cargs;       // The client args
client_conn *conn;        // The client connection struct
rwindow *rwin;            // The receiving window
packet_t *file_name_pkt;  // The file name packet
int sockfd;               // The socket used for communication 
int cliport;              // The client ephemeral port

void
get_conn() {
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

void consume_packets(rwindow *rwin) {
  // TODO First packet number that we receive is 2. We should
  // fix this.
  int next_seq = 1;
  packet_t *pkt;
  
  char file_name[300];
  // Open the file for writing
  sprintf(file_name, "%s.out", "test");

  FILE *pf = fopen(file_name, "w");
  assert(pf);

  do {
    uint32_t sleep_time = 1000, retries = 0;
    pkt = NULL;
    do {
      pthread_mutex_lock(rwin->mutex);
      treap_node *tn = treap_find(&rwin->t_rwin, next_seq);
      pthread_mutex_unlock(rwin->mutex);
      
      // We found the node with the right seq number
      if (tn != NULL) {
        pkt = (packet_t *) (tn->data);
        break;
      }  

      // If the packet that we are expected isn't in the treap,
      // wait for some time.
      usleep(sleep_time);
      
      // If the sleep_time is already more than a second, don't
      // double it.
      sleep_time = (sleep_time > 1000000) 
                    ? sleep_time : sleep_time << 1;
      
      // We will only wait for a packet for at max 100 retries.
      retries++;
    } while (retries < 100);
    
    if (pkt != NULL) {
      // Received the packet.

      pthread_mutex_lock(rwin->mutex);
      treap_delete(&rwin->t_rwin, next_seq);
      pthread_mutex_unlock(rwin->mutex);

      // TODO Actual writing out of the packet to file
#ifdef DEBUG      
      fprintf(stderr, "==== Read packet %d with datalen %d and flags %x ====\n", next_seq, pkt->datalen, pkt->flags);
#endif

      // TODO: Check return value of fwrite(3)
      int ret = fwrite(pkt->data, pkt->datalen, 1, pf);
      // if (ret < 0) {
#ifdef DEBUG
      fprintf(stderr, "fwrite returned with ret = %d\n", ret);
#endif
      //}

      next_seq++;
    } else if (pkt != NULL) {
      // We retried 100 times. Packet, Y U NO COME?
      fprintf(stderr, "Did not receive packet seq %d even after 100 retries\n", next_seq);
      fclose(pf);
      exit(1);
    }
    
  } while (!(pkt->flags & FLAG_FIN));
  fclose(pf);
}

void send_packet(packet_t *pkt) {
  int packet_len = 0;
#ifdef DEBUG
  if (pkt->datalen == 0) {
    int num_bytes = sprintf(pkt->data, "== ack %d : rwinsz %d ==", pkt->ack, pkt->rwinsz);
    packet_len = PACKET_HEADER_SZ + num_bytes;
  } else {
    packet_len = PACKET_SZ;
  }
#else
  if (pkt->datalen == 0) {
    packet_len = PACKET_HEADER_SZ;  
    } else {
    packet_len = PACKET_SZ;
  }
#endif
  Send(sockfd, (void *)pkt, packet_len, conn->is_local ? MSG_DONTROUTE : 0);
}

void
handle_tx_error() {
  err_sys("Error while receiving acknowledgement from server");
}

void
send_filename_pkt() {
  send_packet(file_name_pkt);
}

void 
ack_timeout() {
  fprintf(stderr, "Timed out while waiting for first ack from server\n");
}

void
send_file() {
  int portno;
  struct sockaddr sa;
  struct sockaddr_in *si = (struct sockaddr_in *) &sa;
  socklen_t sa_sz = sizeof(sa);
  
  packet_t pkt;
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

  // Send an ACK to the server.
  pkt.flags = FLAG_ACK;
  pkt.ack   = 1;
  pkt.rwinsz = 10;
  ++pkt.seq;
  pkt.datalen = 0;
  memset(pkt.data, 0, sizeof(pkt.data));
  sprintf(pkt.data, "ACK:1");

  // TODO: Call packet_hton() and pass an output buffer.
  printf("Sending %d bytes of data to the server\n", sizeof(pkt));
  Send(sockfd, (void*)&pkt, sizeof(pkt), conn->is_local ? MSG_DONTROUTE : 0);

  // Receive data from the socket till a packet with the FLAG_FIN flag
  // is received.
 
  // The receiving window
  rwindow rwin;

  // Initialize the receiving window
  rwindow_init(&rwin, cargs->sw_size);
  
  pthread_t tid;
  if (pthread_create(&tid, NULL, (void *) (&consume_packets), (void *) (&rwin)) < 0) {
      err_sys("Could not spawn the consumer thread to read packets");
  }

  while (1) {
      fprintf(stdout, "Waiting on Recv...\n");
      int r = recv(sockfd, (void*)&pkt, sizeof(pkt), 0);
      if (r < 0) {
          // TODO: Handle EINTR.
          perror("recv");
          exit(1);
      }
      fprintf(stdout, "recv(2) returned with exit code: %d and  with seq number: %u\n", r, pkt.seq);
      packet_t *ack_pkt = rwindow_received_packet(&rwin, &pkt);
      fprintf(stdout, "ack_pkt will be sent with ack: %u, rwinsz: %d\n", ack_pkt->ack, ack_pkt->rwinsz);
      // TODO Disable this is if needed. The server doesn't accept ACKs so far.
      // This is only an ACK packet. Hence, PACKET_HEADER_SZ
      fprintf(stderr,  "Sending ack packet\n");
      send_packet(ack_pkt);
      // Send(sockfd, (void *)&ack_pkt, PACKET_HEADER_SZ, conn->is_local ? MSG_DONTROUTE : 0);

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
      // Writing out the packet data must be done in the consumer thread (consume_data())
      // fwrite(pkt.data, pkt.datalen, 1, pf);
      if (pkt.flags & FLAG_FIN) {
          // TODO Here goes the special logic for dealing with FIN
          break;
      }
  }
  // We should exit only when the consumer thread has finished its job
  pthread_join(tid, NULL);
  // We don't want to return to the main thread
  exit(0);
}

// Connect to the server, and send the first datagram
void
initiate_tx() {
  sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

  // Bind to port 0
  Bind(sockfd, conn->cli_sa, sizeof(SA));

  struct sockaddr_in sin;
  UINT addrlen = sizeof(SA);

  // Fetch port number at which kernel bound this socket.
  Getsockname(sockfd, (SA *)&sin, &addrlen);
  cliport = ntohs(sin.sin_port);
  printf("Client's ephemeral Port Number: %d\n", cliport);

  // Connect to the server.
  Connect(sockfd, conn->serv_sa, sizeof(SA));

  // TODO
  // Do we need getpeername here?
  
  // Sending the file name to the server
  // Q. Do we need to pass the conn->serv_sa here?

  // TODO: Start a timer here to re-send the file name till we receive an ACK.
  
  int syn_retries = 0;
  /*
  int portno;
  struct sockaddr sa;
  struct sockaddr_in *si = (struct sockaddr_in *) &sa;
  socklen_t sa_sz = sizeof(sa);
  */
  
  fdset fds;
  struct timeval timeout;
  timeout.tv_sec = 6;
  timeout.tv_usec = 0;

  do {
    timeout.tv_sec = 6;
    timeout.tv_usec = 0;

    fdset_init(&fds, timeout, ack_timeout);

    fdset_add(&fds, &fds.rev, sockfd, &sockfd, send_file);
    fdset_add(&fds, &fds.exev, sockfd, &sockfd, handle_tx_error);
    
    fprintf(stderr, "Trying to send the SYN packet to the Server with the file name\n");

    // Send the packet to the server
    send_filename_pkt();
    
    int r = fdset_poll(&fds, &timeout, ack_timeout);
    // Handle EINTR.
    if (r < 0) {
      perror("select");
      assert(errno != EINTR);
      exit(1);
    }

    syn_retries++;
  } while (syn_retries < 12);
  fprintf(stderr, "Too many retries.\n");
}

int main(int argc, char **argv) {
  assert(argc == 1);
  const char *cargs_file = CARGS_FILE;
  cargs = MALLOC(client_args);
  if (read_cargs((const char *)cargs_file, cargs)) {
    exit(1);
  }
  
  conn = MALLOC(client_conn);
  file_name_pkt = MALLOC(packet_t);
  memset(file_name_pkt, 0, sizeof(packet_t));
  file_name_pkt->ack = 0;
  file_name_pkt->seq = 0;
  file_name_pkt->flags = FLAG_SYN;
  file_name_pkt->datalen = strlen(cargs->file_name);
  strcpy(file_name_pkt->data, cargs->file_name);

  get_conn();
  printf("Server is %s\nIPServer: %s\nIPClient: %s\n", 
          (conn->is_local ? "Local" : "Not Local"),
          sa_data_str(conn->serv_sa),
          sa_data_str(conn->cli_sa));
  // printf("IPServer: %s\n", Sock_ntop(sa, sizeof(SA)));
  initiate_tx();
  return 0;
}
