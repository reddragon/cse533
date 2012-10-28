// -*- mode: c; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "fdset.h"
#include "algorithm.h"
#include "swindow.h"

typedef struct inflight_request {
  int fd; // The fd of the socket on which the request arrived.
  pid_t pid; // The pid of the child process spawned to serve this client.
  struct sockaddr sa; // Connection information.
  struct sockaddr_in si;
} inflight_request;

// A list of ints storing File Descriptors of listening sockets.
vector socklist;

// Stores a list of in-flight requests that have connected, but not yet
// terminated. Useful in case responses from the server are lost and the
// client re-requests stuff.
vector inflight_requests;

// Stores all the information for interfaces in this machine.
vector interfaces;

// The arguments as read from the file server.in
struct server_args sargs;

// The sliding window for this server child.
swindow swin;

BOOL first_call_to_read_some = TRUE;

// The ephemeral port number on the server.
int sport = -1;

// FDs belinging to the server-child.
fdset scfds;

// When was the last call to select(2) made?
uint32_t last_call_to_select = 0;

// The last (dynamic) value of timeout (in ms) used in the select(2)
// system call. Whenever we invoke the data_producer() function, we
// determine the current time, and subtract it from the
// 'last_call_to_select'. This gives us the amount of time that
// select(2) slept. We subtract this from 'last_select_timeout_ms' to
// determine the new timeout for select.
uint32_t last_select_timeout_ms = 0;

uint32_t probe_timeout_ms = 1;

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
  struct ifi_info *ifi = (struct ifi_info*)rhs;
  struct ifi_info *cli_ifi = (struct ifi_info*)lhs;

  char rhs_addr[40], cli_addr[40];
  strcpy(rhs_addr, Sock_ntop_host(ifi->ifi_addr, sizeof(SA)));
  strcpy(cli_addr, Sock_ntop_host(cli_ifi->ifi_addr, sizeof(SA)));

  printf("[1] Comparing Server '%s' and client '%s' IP.\n", rhs_addr, cli_addr);
  if (!strcmp(cli_addr, rhs_addr)) {
    // They are the same.
    printf("Server and client are on the same machine.\n");
    cli_ifi->ifi_myflags = 1;
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

  struct sockaddr *cli_snaddr =  get_subnet_addr(this_ifi->ifi_addr, ifi->ifi_ntmaddr);
  struct sockaddr *serv_snaddr = get_subnet_addr(ifi->ifi_addr,      ifi->ifi_ntmaddr);

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


// TODO: Copy get_conn() to client.
// cli_sa is what we got when we did the initial recvfrom(2) from the client.
void
get_conn(struct sockaddr *cli_sa, struct server_conn *conn) {
  // The port number from which the client makes the connection.
  int cli_portno = ntohs(((struct sockaddr_in *)cli_sa)->sin_port);

  vector *ifaces = get_all_interfaces();
  struct ifi_info cli_ifi;

  memset(&cli_ifi, 0, sizeof(cli_ifi));
  cli_ifi.ifi_addr = cli_sa;
  conn->is_local = FALSE;

  // Check if the server is on the same machine as the client.
  algorithm_reduce(ifaces, is_local_interface_reducer, &cli_ifi);

  // cli_ifi.ifi_myflags is == 1 if the client & server share an IP
  // address.
  if (cli_ifi.ifi_myflags) {
    // Client & server are on the same machine.
    conn->is_local = TRUE;
    conn->cli_sa  = inet_pton_sa("127.0.0.1", cli_portno);
    conn->serv_sa = inet_pton_sa("127.0.0.1", 0);
    return;
  }

  cli_ifi.ifi_myflags = 0; // The length of the longest match.
  algorithm_reduce(ifaces, longest_match_reducer, &cli_ifi);

  if (cli_ifi.ifi_brdaddr) {
    conn->is_local = TRUE;
    conn->cli_sa  = cli_sa;
    char server_ip[40];
    strcpy(server_ip, Sock_ntop_host(cli_ifi.ifi_brdaddr, sizeof(SA)));

    // Server bind(2)s to port 0 (locally) and fetches and ephemeral port number.
    conn->serv_sa = inet_pton_sa(server_ip, 0);
    return;
  }

  // We could not find any local interfaces. Just choose the 1st one
  // at random.
  assert(!vector_empty(ifaces));
  conn->cli_sa  = cli_sa;
  conn->serv_sa = ((struct ifi_info*)vector_at(ifaces, 0))->ifi_addr;
}

int data_producer(void *opaque, void *vbuff, int buffsz) {
  int r = 0;
  FILE *pf = (FILE*)opaque;
  char *buff = (char*)vbuff;

  if (first_call_to_read_some) {
    r = sprintf(buff, "%d", sport);
    first_call_to_read_some = FALSE;
    return r;
  }

  swin.fd2 = -1;
  swin.csa = NULL;

  r = fread(buff, 1, buffsz, pf);
  return r;
}

void on_end_cb(int status) {
  fprintf(stderr, "on_end_cb(%s)\n", (status == TX_SUCCESS ? "SUCCESS" : "FAILURE"));
  if (status == TX_FAILURE) {
    exit(1);
  } else {
    exit(0);
  }
}

void set_new_select_timeout(uint32_t ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  scfds.timeout = tv;
}

void on_advanced_oldest_unACKed_seq(void *opaque) {
  // We reset the timeout value when the oldest unACKed sequence # is
  // advanced.
  uint32_t rto = rtt_get_RTO(&swin.rtt);
  fprintf(stderr, "on_advanced_oldest_unACKed_seq::Updating timeout to %d ms\n", rto);
  set_new_select_timeout(rto);
}

void on_sock_read_ready(void *opaque) {
  packet_t pkt;
  fprintf(stderr, "on_sock_read_ready::Trying read from FD: %d\n", swin.fd);
  probe_timeout_ms = 1;

  // int r = Recv(swin.fd, &pkt, sizeof(pkt), 0);
  int r = recvfrom(swin.fd, &pkt, PACKET_HEADER_SZ, 0, NULL, NULL);
  if (r < 0 && (errno == EINTR || errno == ECONNREFUSED)) {
    perror("recvfrom");
    return;
  }
  fprintf(stderr, "Successfully read %d bytes\n", r);

  // Decrease timeout value by the amount of time spent in the
  // select(2) system call.
  uint32_t current_time = current_time_in_ms();
  uint32_t select_slept_for = current_time - last_call_to_select;
  last_call_to_select = current_time;
  last_select_timeout_ms -= select_slept_for;
  if (last_select_timeout_ms > 500000) {
    // Some unholy value (500sec).
    last_select_timeout_ms = 0;
  }

  set_new_select_timeout(last_select_timeout_ms);
  swindow_received_ACK(&swin, pkt.ack, pkt.rwinsz);
}

void on_sock_error(void *opaque) {
}

void on_select_timeout(void *opaque) {
  last_call_to_select = current_time_in_ms();
  uint32_t rto;

  // Are we in window probe mode? (detected by the value of
  // swin.swinsz).
  if (swin.swinsz == 0) {
    // We are in window probe mode.
    rto = probe_timeout_ms;
    probe_timeout_ms *= 2;
    probe_timeout_ms = imin(60, imax(probe_timeout_ms, 5));
  } else {
    probe_timeout_ms = 1;

    // Double the timeout.
    rtt_scale_RTO(&swin.rtt, 2);

    rto = (uint32_t)rtt_get_RTO(&swin.rtt);
    fprintf(stderr, "on_select_timeout::Updating timeout to %d ms\n", rto);
  }

  set_new_select_timeout(rto);
  swindow_timed_out(&swin);
}

// Most of the heavy lifting happens here
void
start_ftp(int old_sockfd, struct sockaddr* cli_sa, const char *file_name) {
  struct server_conn conn;
  get_conn(cli_sa, &conn);
  printf("Client is %s\nIPServer: %s\nIPClient: %s\n", 
    (conn.is_local ? "Local" : "Not Local"),
    sa_data_str(conn.serv_sa),
    sa_data_str(conn.cli_sa));
  int sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

  set_non_blocking(sockfd);
  // TODO: Set SO_DONTROUTE if required.

  Bind(sockfd, conn.serv_sa, sizeof(SA));
  struct sockaddr_in sin;
  UINT addrlen = sizeof(SA);
  Getsockname(sockfd, (SA *)&sin, &addrlen);
  printf("Client: %s\n", sa_data_str(conn.cli_sa));
  printf("Server's ephemeral Port Number: %d\n", ntohs(sin.sin_port));
  // TODO
  // Finish the ARQ part. This is not reliable

  // TODO: Start a timer after sending the first packet. If the ACK
  // times out, we re-send the port number on both sockets so that the
  // client can respond accordingly. Use select(2) for the connection
  // bit and the actual data sending if possible.

  // Once the 3-way handshake is complete, we set up a sliding window
  // with a static size, and send as many packets as will fit in that
  // window. Once we run out of buffer space, we wait till an ACK
  // comes in and send out more data when the ACK frees up some space
  // in our window.

  // We also set up a timer to track in case no ACKs are coming
  // in. Also, once 3 ACKs come in for a packet, we switch to
  // fast-retransmit and retransmit ONLY that packet and continue
  // processing.

#if 0
  packet_t pkt;
  pkt.ack = 0;
  pkt.seq = 0;
  pkt.flags = FLAG_SYN;
  memset(pkt.data, 0, sizeof(pkt.data));
  pkt.datalen = sprintf(pkt.data, "%d", ntohs(sin.sin_port));

  // Send the new port number on the existing socket.
  Sendto(old_sockfd, (void*)&pkt, sizeof(pkt), MSG_DONTROUTE, conn.cli_sa, sizeof(SA));
#endif

  sport = ntohs(sin.sin_port);
  FILE *pf = fopen(file_name, "r");
  assert(pf);

  swindow_init(&swin, sockfd, old_sockfd, conn.cli_sa,
               sargs.sw_size, 1, data_producer,
               pf, on_advanced_oldest_unACKed_seq, on_end_cb);

  // Connect this socket to the client on the original port that the
  // client sent data from.
  printf("Client has connected from port: %d\n", ntohs(((struct sockaddr_in*)(conn.cli_sa))->sin_port));
  Connect(sockfd, conn.cli_sa, sizeof(SA));

  struct timeval timeout;
  timeout.tv_sec = 20;
  timeout.tv_usec = 0;

  // Set up the callbacks.
  fdset_init(&scfds, timeout, on_select_timeout);
  fdset_add(&scfds, &scfds.rev,  sockfd, NULL, on_sock_read_ready);
  fdset_add(&scfds, &scfds.exev, sockfd, NULL, on_sock_error);

  // Start sending the packets.
  swindow_received_ACK(&swin, 0, 1);

  int r;

  last_call_to_select    = current_time_in_ms();
  last_select_timeout_ms = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
  r = fdset_poll2(&scfds);

#if 0
  // Once the client sends back an ACK on the new socket we connected
  // from, we can proceed with the file transfer. Wait for the ACK.
  r = Recv(sockfd, (void*)&pkt, sizeof(pkt), 0);

  // Send data till we have more data to write.
  pkt.flags = 0;
  while (1) {
    memset(pkt.data, 0, sizeof(pkt.data));
    int bread = fread(pkt.data, 1, sizeof(pkt.data), pf);
    if (bread == 0) {
      pkt.flags = FLAG_FIN;
    }
    pkt.datalen = bread;
    ++pkt.seq;
    fprintf(stdout, "Sending %d bytes of file data for packet %u\n", bread, pkt.seq);
    Send(sockfd, (void*)&pkt, sizeof(pkt), MSG_DONTROUTE);
    if (bread == 0) {
      break;
    }
  }

  fclose(pf);
  close(sockfd);
#endif

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
    set_non_blocking(sockfd);

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

void main_server_read_cb(void *opaque) {
  int fd = *(int*)opaque;
  printf("There is a disturbance in the force at fd '%d'\n", fd);
  char file_name[256];
  struct sockaddr cli_sa;
  struct sockaddr_in *cli_si = (struct sockaddr_in *) &cli_sa;
  socklen_t sa_sz = sizeof(cli_sa);
  int r;
  packet_t pkt;

  // Handle return value return from callback in case if EINTR. Since
  // we are using level triggered multiplexed I/O we will be invoked
  // again in case we didn't read anything when there was something to
  // read.
  r = recvfrom(fd, (void*)&pkt, sizeof(pkt), 0, &cli_sa, &sa_sz);
  if (r < 0 && errno == EINTR) {
    return;
  }

  if (r < 0) {
    perror("recvfrom");
    printf("Error getting file name from the client\n");
    return;
  }

  assert(pkt.datalen < sizeof(pkt.data));
  pkt.data[pkt.datalen] = '\0';
  strcpy(file_name, pkt.data);
  printf("%s:%u requested file '%s'\n", sa_data_str(&cli_sa), ntohs(cli_si->sin_port), file_name);

#if 0
  // TODO: Check if this is a re-request for an in-flight request.
  inflight_request req;
  req.fd = fd;
  req.sa = cli_sa;
  req.si = *si;
  int pos = algorithm_find(inflight_requests, req, find_inflight_request);

  if (pos != -1) {
    req = *(inflight_request*)vector_at(&inflight_requests, pos);

    // Check if the process is running.
    if (kill(pid, 0) != 0) {
      pos = -1;
    }
  }

  if (pos != -1) {
    // Process is running - do nothing.
    return;
  }
#endif

  int pid = fork();
  if (pid < 0) {
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
      if (sockfd != fd) {
        // close(sockfd);
      }
    }

    // TODO: Add to list of in-flight requests.
    start_ftp(fd, &cli_sa, file_name);
    printf("Child process exiting\n");
    exit(0);
  } // if (pid == 0)
}

void main_server_ex_cb(void *opaque) {
  int fd = *(int*)opaque;
  printf("Error detected on fd '%d'\n", fd);
}

void main_server_timeout_cb(void *opaque) {
  printf("Timeout in select(2)\n");
}

int main(int argc, char **argv) {
  const char *sargs_file = SARGS_FILE;
  int i, r;

  utils_init();
  vector_init(&socklist, sizeof(int));
  vector_init(&interfaces, sizeof(struct ifi_info));
  read_sargs(sargs_file, &sargs);
  bind_udp(&sargs, &socklist);

  fdset fds;
  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  fdset_init(&fds, timeout, main_server_timeout_cb);

  // Add every socket in socklist to fds->rev & fds->exev
  for (i = 0; i < vector_size(&socklist); ++i) {
    int *pfd = (int*)vector_at(&socklist, i);
    fdset_add(&fds, &fds.rev,  *pfd, pfd, main_server_read_cb);
    fdset_add(&fds, &fds.exev, *pfd, pfd, main_server_ex_cb  );
    printf("Added FD %d to read/ex-set\n", *pfd);
  }

  r = fdset_poll(&fds, &timeout, main_server_timeout_cb);

  if (r < 0) {
    perror("select");
    assert(errno != EINTR);
    exit(1);
  }

  return 0;
}
