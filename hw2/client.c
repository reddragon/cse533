// -*- mode: c; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <math.h>
#include "utils.h"
#include "rwindow.h"
#include "fdset.h"
#include "perhaps.h"
#include "algorithm.h"
#include "email.h"

client_args *cargs;       // The client args
client_conn *conn;        // The client connection struct
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
rwindow rwin;             // The receiving window
pthread_t tid;            // The consumer thread
int syn_retries = 0;      // The # of times we re-tried sending the file name packet. We quit after successive 12 timeouts
vector interfaces;        // Stores information for the interfaces in this machine


// The arguments read from the client.in file
struct client_args *cargs = NULL;

void on_client_exit(void) {
  struct timeval tv;
  VERBOSE("Failed Calls to recv(2) or recvfrom(2): %d/%d = %.2f\n",
          recv_failed, recv_total, (double)recv_failed/(double)recv_total);
  VERBOSE("Failed Calls to send(2)               : %d/%d = %.2f\n",
          send_failed, send_total, (double)send_failed/(double)send_total);

  Gettimeofday(&tv, NULL);
  time_t currtime;
  char str_time[40];
  strftime(str_time, 40, "%T", localtime(&currtime));
  INFO("Client exited at %s.%03u\n", str_time, (unsigned int)tv.tv_usec/1000);
}

vector* get_all_interfaces(void) {
  if (!vector_empty(&interfaces)) {
    return &interfaces;
  }
  struct ifi_info *ifi, *ifi_head = Get_ifi_info_plus(AF_INET, 0);

  for (ifi = ifi_head; ifi != NULL; ifi = ifi->ifi_next) {
    vector_push_back(&interfaces, ifi);
  }
  return &interfaces;
}

const void* is_local_interface_reducer(const void *lhs, const void *rhs) {
  struct ifi_info *serv_ifi = (struct ifi_info*)lhs;
  struct ifi_info *cli_ifi = (struct ifi_info*)rhs;

  char serv_addr[40], cli_addr[40];
  strcpy(cli_addr,  Sock_ntop_host(cli_ifi->ifi_addr,  sizeof(SA)));
  strcpy(serv_addr, Sock_ntop_host(serv_ifi->ifi_addr, sizeof(SA)));

  printf("[1] Comparing Client '%s' and server '%s' IP.\n", cli_addr, serv_addr);
  if (!strcmp(cli_addr, serv_addr)) {
    // They are the same.
    printf("Server and client are on the same machine.\n");
    serv_ifi->ifi_myflags = 1;
  }
  return lhs;
}

const void* longest_match_reducer(const void *lhs, const void *rhs) {
  struct ifi_info *ifi = (struct ifi_info*)rhs;
  struct ifi_info *this_ifi = (struct ifi_info*)lhs;

  // Now check if (server's IP addr & server network mask) is the
  // same as (client's IP addr & client network mask). If yes,
  // store it. (Only if the prefix match is longer than any
  // previous prefix match found, thus far).

  char serv_snaddr_str[40], cli_snaddr_str[40];

  struct sockaddr *serv_snaddr = get_subnet_addr(this_ifi->ifi_addr,
                                                 ifi->ifi_ntmaddr);
  struct sockaddr *cli_snaddr  = get_subnet_addr(ifi->ifi_addr,
                                                 ifi->ifi_ntmaddr);

  strcpy(serv_snaddr_str, Sock_ntop_host(serv_snaddr, sizeof(SA)));
  strcpy(cli_snaddr_str,  Sock_ntop_host(cli_snaddr,  sizeof(SA)));

  free(cli_snaddr);
  free(serv_snaddr);

  // this_ifi->ifi_myflags stores the length of the longet prefix, and
  // this_ifi->ifi_brdaddr stores the actual entry that is the longest.

  UINT ntm_len = get_ntm_len(ifi->ifi_ntmaddr);

  printf("[2] Comparing Server '%s' and Client '%s' IP. len(netmask): %d\n", serv_snaddr_str, cli_snaddr_str, ntm_len);
  if (!strcmp(serv_snaddr_str, cli_snaddr_str) && ntm_len > this_ifi->ifi_myflags) {
    printf("Server IP '%s' matches client IP '%s' with length '%d'\n", serv_snaddr_str, cli_snaddr_str, ntm_len);
    this_ifi->ifi_myflags = ntm_len;
    this_ifi->ifi_brdaddr = ifi->ifi_addr;
  }
  return lhs;
}

void get_conn(client_conn *conn) {
  const char *server_ip = (const char*)cargs->ip_addr;
  int server_port = cargs->serv_portno;
  struct sockaddr *serv_sa = inet_pton_sa(server_ip, server_port);

  vector *ifaces = get_all_interfaces();
  struct ifi_info serv_ifi;

  memset(&serv_ifi, 0, sizeof(serv_ifi));
  serv_ifi.ifi_addr = serv_sa;
  conn->is_local = FALSE;

  // Check if the server is on the same machine as the client.
  algorithm_reduce(ifaces, is_local_interface_reducer, &serv_ifi);

  // serv_ifi.ifi_myflags is == 1 if the client & server share an IP
  // address.
  if (serv_ifi.ifi_myflags) {
    // Client & server are on the same machine.
    conn->is_local = TRUE;
    conn->cli_sa  = inet_pton_sa("127.0.0.1", 0);
    conn->serv_sa = inet_pton_sa("127.0.0.1", server_port);
    return;
  }

  serv_ifi.ifi_myflags = 0; // The length of the longest match.
  algorithm_reduce(ifaces, longest_match_reducer, &serv_ifi);

  if (serv_ifi.ifi_brdaddr) {
    conn->is_local = TRUE;
    conn->serv_sa  = serv_sa;
    char client_ip[40];
    strcpy(client_ip, Sock_ntop_host(serv_ifi.ifi_brdaddr, sizeof(SA)));

    // Client bind(2)s to port 0 (locally).
    conn->cli_sa = inet_pton_sa(client_ip, 0);
    return;
  }

  // We could not find any local interfaces that match. Let the kernel
  // choose the outgoing interface for us.
  fprintf(stderr, "serv_sa: %s\n", Sock_ntop(serv_sa, sizeof(*serv_sa)));
  conn->cli_sa  = inet_pton_sa("0.0.0.0", 0);
  conn->serv_sa = serv_sa;
}

void *consume_packets(rwindow *rwin) {
  // First packet number that we receive is one with SEQ #1
  int next_seq = 1;
  packet_t *pkt;

#ifdef DEBUG
  char file_name[300];
  // Open the file for writing
  sprintf(file_name, "%s.out", "test");

  FILE *pf = fopen(file_name, "w");
  ASSERT(pf);
#endif

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
      VERBOSE("==== Read packet %d with datalen %d and flags %x, treap_sz: %d ====\n", next_seq, pkt->datalen, pkt->flags, treap_sz);
      int ret = fwrite(pkt->data, pkt->datalen, 1, pf);
      VERBOSE("fwrite returned with ret = %d\n", ret);
#else
      if (!(pkt->flags & FLAG_FIN)) {
        INFO("\n==== BEGIN PACKET #%d DATA ==="
             "\n%s"
             "\n====  END PACKET #%d DATA  ===\n",
             pkt->seq, pkt->data, pkt->seq);
      }
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
    VERBOSE("sleep_time: %lf\n", sleep_time);
#endif
    usleep(sleep_time * 1000);
  } while (1);

#ifdef DEBUG
  fclose(pf);
#endif
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
     r = perhaps_rarely_send(sockfd, (void *)&tp, packet_len, 0);
  } else {
     r = perhaps_send(sockfd, (void *)&tp, packet_len, 0);
  }
#else
  int r = perhaps_send(sockfd, (void *)&tp, packet_len, 0);
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
  INFO("Timed out %d times while waiting for first ack from server\n", ++syn_retries);
  if (syn_retries > 12) {
    exit(1);
  }

  // Send the packet again and reset timeout.
  send_filename_pkt();
  fds.timeout.tv_sec = 3;
  fds.timeout.tv_usec = 0;
}

void resend_fin_pkt(void *opaque) {
  INFO("Resending the ACK in response to the FIN%s\n", "");

  packet_t pkt;
  // Read the packet from the socket.
  recv_packet(&pkt);

  uint32_t cur_ms = current_time_in_ms();
  uint32_t elapsed_ms = cur_ms - at_select_ms;
  if (elapsed_ms <= time_av_ms) {
    time_av_ms -= elapsed_ms;
    at_select_ms = cur_ms;
  } else {
    time_av_ms = 0;
  }
  fds.timeout.tv_sec = time_av_ms / 1000;
  fds.timeout.tv_usec = (time_av_ms % 1000) * 1000;

  send_packet(fin_pkt);
  INFO("Waiting for %d more seconds in the FIN_WAIT state\n", time_av_ms/1000);
}

void fin_timeout(void *opaque) {
  INFO("Timed out after waiting for 60 secs after getting a FIN%s\n", "");

  // We should exit only when the consumer thread has finished its job
  pthread_join(tid, NULL);

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
    if (errno == EINTR || errno == ECONNREFUSED) {
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

  INFO("Server endpoints {1} [%s:%d] & {2} [%s:%d]\n", serverIP, ntohs(si->sin_port), serverIP, portno);

  /*
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
  */

  // We open a new socket and dup2() since nothing else seems to be
  // working on both Linux as well as Solaris.
  int new_sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
  dup2(new_sockfd, sockfd);
  if (conn->is_local) {
    set_dontroute(sockfd);
  }

  // Bind to the port we were originally bound to, and connect this
  // socket to the new port number that the server sent us.
  struct sockaddr_in cli_si;
  memset(&cli_si, 0, sizeof(cli_si));
  memcpy(&cli_si, conn->cli_sa, sizeof(struct sockaddr));
  cli_si.sin_port = htons(cliport);
  Bind(sockfd, (struct sockaddr*)&cli_si, (socklen_t)sizeof(struct sockaddr_in));

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

  INFO("Sending %d bytes of data to the server\n", sizeof(pkt));
  send_packet(&pkt);

  // Receive data from the socket till a packet with the FLAG_FIN flag
  // is received.
 
  if (pthread_create(&tid, NULL, (void *) (&consume_packets), (void *) (&rwin)) < 0) {
      err_sys("Could not spawn the consumer thread to read packets");
  }

  while (1) {
      VERBOSE("Waiting on recv(2)...%s\n", "");
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
      VERBOSE("recv(2) read %d bytes. Packet seq#: %u\n", r, pkt.seq);
      packet_t *ack_pkt = rwindow_received_packet(&rwin, &pkt);
      INFO("ACK Packet will be sent with ACK: %u, Window Size: %d\n", ack_pkt->ack, ack_pkt->rwinsz);
      if (pkt.flags & FLAG_FIN) {
        fin_pkt = ack_pkt;
      } 

      send_packet(ack_pkt);
      
      if (pkt.flags & FLAG_FIN) {
          // Here goes the special logic for dealing with FIN
          fdset_remove(&fds, &fds.rev, sockfd);
          fds.timeout_cb = fin_timeout;
          fdset_add(&fds, &fds.rev, sockfd, &sockfd, resend_fin_pkt);
          fds.timeout.tv_sec = 60;
          fds.timeout.tv_usec = 0;
          
          time_av_ms = 60*1000;
          at_select_ms = current_time_in_ms();
          INFO("Entering the TIME_WAIT state%s\n", "");
          return;
      } 
      
      free(ack_pkt);
      ack_pkt = NULL;
  } // while (1)
}

// Connect to the server, and send the first datagram
void initiate_tx(void) {
  sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
  if (conn->is_local) {
    set_dontroute(sockfd);	
  }

  // Bind to port 0
  Bind(sockfd, conn->cli_sa, (socklen_t)sizeof(SA));

  struct sockaddr_in sin;
  UINT addrlen = sizeof(SA);

  // Fetch port number at which kernel bound this socket.
  Getsockname(sockfd, (SA *)&sin, &addrlen);
  cliport = ntohs(sin.sin_port);
  INFO("Client's ephemeral Port Number: %d\n", cliport);

  // Connect to the server.
  Connect(sockfd, conn->serv_sa, sizeof(SA));

  // TODO
  // Do we need getpeername here?
  
  // Start a timer here to re-send the file name till we receive an
  // ACK.

  struct timeval timeout;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, ack_timeout);

  fdset_add(&fds, &fds.rev, sockfd, &sockfd, send_file);
  fdset_add(&fds, &fds.exev, sockfd, &sockfd, handle_tx_error);

  // Send the packet to the server
  INFO("Trying to send the SYN packet to the Server with the file name%s\n", "");
  send_filename_pkt();

  int r = fdset_poll2(&fds);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

int main(int argc, char **argv) {
  atexit(on_client_exit);

  const char *cargs_file = CARGS_FILE;
  cargs = MALLOC(client_args);
  if (read_cargs((const char *)cargs_file, cargs)) {
      exit(1);
  }
  
  utils_init();
  perhaps_init();
  vector_init(&interfaces, sizeof(struct ifi_info));

  // Initialize the receiving window
  rwindow_init(&rwin, cargs->sw_size);

  get_all_interfaces();

  // Call print_ifi_info().
  print_ifi_info((struct ifi_info*)vector_at(&interfaces, 0));

  conn = MALLOC(client_conn);
  file_name_pkt = MALLOC(packet_t);
  memset(file_name_pkt, 0, sizeof(packet_t));
  file_name_pkt->ack = 0;
  file_name_pkt->seq = 0;
  file_name_pkt->flags = FLAG_SYN;
  file_name_pkt->datalen = strlen(cargs->file_name);
  strcpy(file_name_pkt->data, cargs->file_name);

  get_conn(conn);
  INFO("Server is %s\nIPServer: %s\nIPClient: %s\n", 
       (conn->is_local ? "Local" : "Not Local"),
       sa_data_str(conn->serv_sa),
       sa_data_str(conn->cli_sa));
  initiate_tx();
  return 0;
}
