#ifndef _UTILS_H_
#define _UTILS_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "unpifiplus.h"

#define UINT unsigned int
#define BOOL unsigned short
#define FALSE 0
#define TRUE 1
#define MALLOC(X) (X *) my_malloc(sizeof(X))

#define CARGS_FILE "client.in"
#define SARGS_FILE "server.in"
#define MAXSOCKS 100

void* my_malloc(size_t size);


struct client_args {
  char ip_addr[20];
  UINT serv_portno;
  char file_name[100];
  UINT sw_size;
  UINT rand_seed;
  double p; // Prob. of packet loss
  double mean; // Mean
};

struct client_conn {
  struct sockaddr *serv_sa;
  struct sockaddr *cli_sa;
  BOOL is_local; // Is the server local?
};

struct server_conn {
  struct sockaddr *serv_sa;
  struct sockaddr *cli_sa;
  BOOL is_local; // Is the client local?
};

struct server_args {
  UINT serv_portno;
  UINT sw_size;
};

enum {
    FLAG_ACK = 1,
    FLAG_FIN = 2,
    FLAG_SYN = 4
};

typedef struct packet_t {
    uint32_t ack;      // The seq # of the packet we are ACKing (only filled in by the client)
    uint32_t seq;      // The seq # of the packet being set (only filled in by the server)
    uint32_t rwinsz;   // The size of the receiving window (only filled in by the client)
    uint16_t flags;    // FLAGS
    uint16_t datalen;  // The length of the data being sent (only filled in by the server)
    char data[512-16]; // The actual data. The client can send packets that don't have the data field
} packet_t;

uint32_t current_time_in_ms(void);
void     packet_hton(packet_t *out, const packet_t *in);
void     packet_ntoh(packet_t *out, const packet_t *in);
char*    strip(char *s);
void     set_non_blocking(int fd);
void     set_blocking(int fd);

int read_cargs(const char *cargs_file, struct client_args *cargs);
int read_sargs(const char *sargs_file, struct server_args *sargs);
struct ifi_info * Get_ifi_info_plus(int family, int doaliases);
void print_ifi_info(struct ifi_info *ifi);
struct sockaddr* get_subnet_addr(struct sockaddr *addr, struct sockaddr *ntm);
char *sa_data_str(struct sockaddr *sa);
UINT get_ntm_len(struct sockaddr *ntm);
struct sockaddr *inet_pton_sa(const char *ip_addr, UINT portno);
#endif
