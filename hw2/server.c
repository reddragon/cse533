// -*- mode: c; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "fdset.h"
#include "algorithm.h"

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

void
get_conn(struct sockaddr *cli_sa, struct server_conn *conn) {
  // TODO
  // Check if this function is fine
  // Use static/global variables to avoid calling Get_ifi_info_plus() every time.
  struct ifi_info *ifi_head = Get_ifi_info_plus(AF_INET, 0), *ifi;
  struct sockaddr* sa = NULL;
  int cli_portno = ntohs(((struct sockaddr_in *)cli_sa)->sin_port);
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

    // TODO: Make a copy here since we will free ifi_head later.
    conn->serv_sa = ifi_head->ifi_addr;
    conn->cli_sa = cli_sa;
  }

  // TODO: free(3) the ifi_head here

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
  printf("Server's ephemeral Port Number: %d\n", ntohs(sin.sin_port));
  // TODO
  // Finish the ARQ part. This is not reliable

  packet_t pkt;
  pkt.ack = 0;
  pkt.seq = 0;
  pkt.flags = FLAG_SYN;
  pkt.datalen = sprintf(pkt.data, "%d", ntohs(sin.sin_port));

  // Send the new port number on the existing socket.
  Sendto(old_sockfd, (void*)&pkt, sizeof(pkt), MSG_DONTROUTE, conn.cli_sa, sizeof(SA));

  // Once the client sends back an ACK on the new socket we connected
  // from, we can proceed with the file transfer.

  sleep(2);

  // Connect this socket to the client on the original port that the
  // client sent data from.
  printf("Client connected from port: %d\n", ntohs(((struct sockaddr_in*)(conn.cli_sa))->sin_port));
  Connect(sockfd, conn.cli_sa, sizeof(SA));

  // Send data till we have more data to write.
  FILE *pf = fopen(file_name, "r");
  assert(pf);

  pkt.flags = 0;
  while (1) {
    memset(pkt.data, 0, sizeof(pkt.data));
    int bread = fread(pkt.data, 1, 512, pf);
    if (bread == 0) {
      pkt.flags = FLAG_FIN;
    }
    pkt.datalen = bread;
    ++pkt.seq;
    fprintf(stdout, "Sending %d bytes of file data\n", bread);
    Send(sockfd, (void*)&pkt, sizeof(pkt), MSG_DONTROUTE);
    // , conn.cli_sa, sizeof(SA));
    if (bread == 0) {
      break;
    }
  }

  fclose(pf);
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

void read_cb(void *opaque) {
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

  assert(pkt.datalen < 512);
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
        close(sockfd);
      }
    }

    // TODO: Add to list of in-flight requests.
    ftp(fd, &cli_sa, file_name);
    printf("Child process exiting\n");
    exit(0);
  } // if (pid == 0)
}

void ex_cb(void *opaque) {
  int fd = *(int*)opaque;
  printf("Error detected on fd '%d'\n", fd);
}

void timeout_cb(void *opaque) {
  printf("Timeout in select(2)\n");
}

int main(int argc, char **argv) {
  const char *sargs_file = SARGS_FILE;
  struct server_args sargs;
  int i, r;

  vector_init(&socklist, sizeof(int));
  read_sargs(sargs_file, &sargs);
  bind_udp(&sargs, &socklist);

  fdset fds;
  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  fdset_init(&fds);

  // Add every socket in socklist to fds->rev & fds->exev
  for (i = 0; i < vector_size(&socklist); ++i) {
    int *pfd = (int*)vector_at(&socklist, i);
    fdset_add(&fds, &fds.rev,  *pfd, pfd, read_cb);
    fdset_add(&fds, &fds.exev, *pfd, pfd, ex_cb  );
    printf("Added FD %d to read/ex-set\n", *pfd);
  }

  r = fdset_poll(&fds, &timeout, timeout_cb);

  // Handle EINTR.
  if (r < 0) {
    perror("select");
    assert(errno != EINTR);
    exit(1);
  }

  return 0;
}
