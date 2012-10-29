// -*- mode: c; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include "utils.h"
#include "rwindow.h"
#include "fdset.h"
#include "perhaps.h"

client_args *cargs;       // The client args
client_conn *conn;        // The client connection struct
rwindow *rwin;            // The receiving window
packet_t *file_name_pkt;  // The file name packet
packet_t *fin_pkt;        // The final packet to be sent
int sockfd;               // The socket used for communication 
int cliport;              // The client ephemeral port
int recv_total = 0;       // Total calls to recv(2) or recvfrom(2)
int recv_failed = 0;      // # of calls to recv(2) or recvfrom(2) that failed
int send_total = 0;       // Total calls to send(2)
int send_failed = 0;      // # of calls to send(2) that failed
fdset fds;                // fdset for the client socket
uint32_t time_av_ms;      // Time available for select(2)    
uint32_t at_select_ms;    // Time available for select(2)    

// The arguments read from the client.in file
struct client_args *cargs = NULL;

void on_client_exit(void) {
  struct timeval tv;
  printf("Failed Calls to recv(2) or recvfrom(2): %d/%d = %.2f\n"
         "Failed Calls to send(2)               : %d/%d = %.2f\n",
         recv_failed, recv_total, (double)recv_failed/(double)recv_total,
         send_failed, send_total, (double)send_failed/(double)send_total);

  Gettimeofday(&tv, NULL);
  printf("Client exited at %u:%u\n", (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec);
}

void get_conn(void) {
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
    conn->cli_sa = MALLOC(struct sockaddr);
    memcpy(conn->cli_sa, ifi_head->ifi_addr, sizeof(struct sockaddr));
    conn->serv_sa = inet_pton_sa((const char *)cargs->ip_addr, cargs->serv_portno);
  }
}

void *consume_packets(rwindow *rwin) {
  // TODO First packet number that we receive is 2. We should
  // fix this.
  int next_seq = 1;
  packet_t *pkt;
  
  srand48(cargs->rand_seed);

  char file_name[300];
  // Open the file for writing
  sprintf(file_name, "%s.out", "test");

  FILE *pf = fopen(file_name, "w");
  assert(pf);
  
  double sleep_time;
  BOOL last_pkt_found = FALSE;
  
  do {
    pthread_mutex_lock(rwin->mutex);
    treap_node *tn = treap_find(&rwin->t_rwin, next_seq);
    while (tn != NULL) {
      pkt = (packet_t *) tn->data;
      treap_delete(&rwin->t_rwin, next_seq);
#if DEBUG
      int treap_sz = treap_size(&rwin->t_rwin);
      fprintf(stderr, "==== Read packet %d with datalen %d and flags %x, treap_sz: %d ====\n", next_seq, pkt->datalen, pkt->flags, treap_sz);
#endif
      int ret = fwrite(pkt->data, pkt->datalen, 1, pf);
      // if (ret < 0) {
#ifdef DEBUG
      fprintf(stderr, "fwrite returned with ret = %d\n", ret);
#endif

      if (pkt->flags & FLAG_FIN) {
        last_pkt_found = TRUE;
        break;
      }
      
      next_seq++;
      tn = treap_find(&rwin->t_rwin, next_seq);
    }
    pthread_mutex_unlock(rwin->mutex);

    if (last_pkt_found) {
      break;
    }
    
    sleep_time = -1.0 * cargs->mean * log(drand48());
#ifdef DEBUG
    fprintf(stderr, "sleep_time: %lf\n", sleep_time);
#endif
    usleep(sleep_time * 1000);
  } while (1);
  fclose(pf);
  return NULL;
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
  packet_t tp = *pkt;
  packet_hton(&tp, pkt);
#ifdef DEBUG
  int r;
  if (pkt == fin_pkt) {
     r = perhaps_rarely_send(sockfd, (void *)&tp, packet_len, conn->is_local ? MSG_DONTROUTE : 0);
  } else {
     r = perhaps_send(sockfd, (void *)&tp, packet_len, conn->is_local ? MSG_DONTROUTE : 0);
  }
#else
  int r = perhaps_send(sockfd, (void *)&tp, packet_len, conn->is_local ? MSG_DONTROUTE : 0);
#endif
  if (r < 0 && errno == EINTR) {
    return;
  } else if (r < 0) {
    perror("send");
    exit(1);
  }
}

int recv_packet(packet_t *pkt) {
  int r = perhaps_recv(sockfd, (void *)pkt, sizeof(*pkt), 0);
  if (r == sizeof(*pkt)) {
    packet_ntoh(pkt, pkt);
  }
  return r;
}

void handle_tx_error(void *opaque) {
  err_sys("Error while receiving acknowledgement from server");
}

void send_filename_pkt(void) {
  send_packet(file_name_pkt);
}

void ack_timeout(void *opaque) {
  fprintf(stderr, "Timed out while waiting for first ack from server\n");
}

void resend_fin_pkt(void *opaque) {
  fprintf(stderr, "Resending the ACK in response to the FIN\n");
  uint32_t cur_ms = current_time_in_ms();
  uint32_t elapsed_ms = cur_ms - at_select_ms;
  if (elapsed_ms <= time_av_ms) {
    time_av_ms -= elapsed_ms;
    at_select_ms = cur_ms;
  } else {
    time_av_ms = 0;
  }
  fds.timeout.tv_sec = time_av_ms / 1000;
  fds.timeout.tv_sec = (time_av_ms % 1000) * 1000;

  send_packet(fin_pkt);
}

void fin_timeout(void *opaque) {
  fprintf(stderr, "Timed out after waiting for 60 secs after getting a FIN\n");
  exit(0);
}

void get_timeval(struct timeval *tv, int ms) {
  if (ms < 0) {
    ms = 0;
  }
  tv->tv_sec = ms / 1000;
  tv->tv_usec = (ms % 1000) * 1000;
}


void send_file(void *opaque) {
  int portno;
  struct sockaddr sa;
  struct sockaddr_in *si = (struct sockaddr_in *) &sa;
  socklen_t sa_sz = sizeof(sa);
  
  packet_t pkt;
  int r;
  r = perhaps_recvfrom(sockfd, (void*)&pkt, sizeof(pkt), 0, &sa, &sa_sz);
  if (r < 0) {
    if (errno == EINTR) {
      // We return from this function in the hope that the next time
      // 'sockfd' is read ready, we will be invoked again.
      return;
    } else {
      perror("recvfrom");
      exit(1);
    }
  }
  packet_ntoh(&pkt, &pkt);

  pkt.data[pkt.datalen] = '\0';
  sscanf(pkt.data, "%d", &portno);
  const char *serverIP = sa_data_str(&sa);

  printf("Server endpoints {1} [%s:%d] & {2} [%s:%d]\n", serverIP, ntohs(si->sin_port), serverIP, portno);

  // Disconnect port association.
  sa.sa_family = AF_UNSPEC;
  Connect(sockfd, &sa, sizeof(SA));

  // Bind to the port we were originally bound to, and connect this
  // socket to the new port number that the server sent us.
  struct sockaddr cli_sa;
  struct sockaddr_in *cli_si = (struct sockaddr_in*)&cli_sa;
  memset(&cli_sa, 0, sizeof(cli_sa));
  memcpy(&cli_sa, conn->cli_sa, sizeof(struct sockaddr));
  cli_si->sin_port = htons(cliport);
  Bind(sockfd, &cli_sa, (socklen_t)sizeof(struct sockaddr_in));

  sa = *(conn->serv_sa);
  si->sin_port = htons(portno);
  Connect(sockfd, &sa, sizeof(SA));

  // Send an ACK to the server.
  pkt.flags = FLAG_ACK;
  pkt.ack   = 1;
  pkt.rwinsz = cargs->sw_size;
  ++pkt.seq;
  pkt.datalen = 0;
  memset(pkt.data, 0, sizeof(pkt.data));
  sprintf(pkt.data, "ACK:%d, RWINSZ: %d", pkt.ack, pkt.rwinsz);

  printf("Sending %d bytes of data to the server\n", sizeof(pkt));
  send_packet(&pkt);

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
      fprintf(stdout, "Waiting on recv(2)...\n");
      int r = recv_packet(&pkt);
      if (r < 0) {
        // Handle EINTR.
        if (errno == EINTR) {
          // Go back to waiting for a packet.
          continue;
        } else {
          perror("recv");
          exit(1);
        }
      }
      fprintf(stdout, "recv(2) read %d bytes. Packet seq#: %u\n", r, pkt.seq);
      packet_t *ack_pkt = rwindow_received_packet(&rwin, &pkt);
      fprintf(stdout, "ack_pkt will be sent with ack: %u, rwinsz: %d\n", ack_pkt->ack, ack_pkt->rwinsz);
      if (pkt.flags & FLAG_FIN) {
        fin_pkt = ack_pkt;
      } 

      send_packet(ack_pkt);
      
      if (pkt.flags & FLAG_FIN) {
          // Here goes the special logic for dealing with FIN
          
          /*
          struct timeval init_time, cur_time, timeout;
          Gettimeofday(&init_time, NULL);
          int init_time_ms, cur_time_ms, time_left_ms;
          init_time_ms = init_time.tv_sec * 1000 + init_time.tv_usec / 1000;
          */

          fdset_remove(&fds, &fds.rev, sockfd);
          fds.timeout_cb = fin_timeout;
          fdset_add(&fds, &fds.rev, sockfd, &sockfd, resend_fin_pkt);
          fds.timeout.tv_sec = 60;
          fds.timeout.tv_usec = 0;
          
          time_av_ms = 60*1000;
          at_select_ms = current_time_in_ms();
          return;
      } 
      
      free(ack_pkt);
      ack_pkt = NULL;
  }
  // We should exit only when the consumer thread has finished its job
  pthread_join(tid, NULL);
  // We don't want to return to the main thread
  exit(0);
}

// Connect to the server, and send the first datagram
void initiate_tx(void) {
  sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

  // Bind to port 0
  Bind(sockfd, conn->cli_sa, (socklen_t)sizeof(SA));

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

  // Start a timer here to re-send the file name till we receive an ACK.
  
  int syn_retries = 0;
    
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
    
    int r = fdset_poll2(&fds);
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
  atexit(on_client_exit);

  assert(argc == 1);
  const char *cargs_file = CARGS_FILE;
  cargs = MALLOC(client_args);
  if (read_cargs((const char *)cargs_file, cargs)) {
      exit(1);
  }
  
  utils_init();
  perhaps_init();
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
