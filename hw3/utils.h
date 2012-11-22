#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>      
#include <linux/if.h>
#include <assert.h>
#include "myassert.h"
#include "unp.h"

#define SRV_DGPATH "/tmp/dynamic_duo/srv_dsock"
#define ODR_DGPATH "/tmp/dynamic_duo/odr_dsock"
#define TIME_SERVER_PORT 7700

#define BOOL  unsigned int
#define FALSE 0
#define TRUE  1

#define TIMESTAMPMSG(TYPE, X, VARGS...) {     \
  fprintf(stdout, TYPE ": " X, VARGS);        \
  fflush(stdout);                             \
}

#if 1
#define VERBOSE(X, VARGS...) TIMESTAMPMSG("VERBOSE", X, VARGS)
#else
#define VERBOSE(X...)
#endif

#define INFO(X, VARGS...) TIMESTAMPMSG("INFO", X, VARGS)
#define MALLOC(X) (X *) my_malloc(sizeof(X))
#define NMALLOC(X,N) (X *) my_malloc(sizeof(X) * N)

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

void* my_malloc(size_t size);

typedef struct eth_addr_t {
    char eth_addr[6];
} eth_addr_t;

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};

typedef struct cli_dsock {
  struct sockaddr_un cliaddr;
  int sockfd;
} cli_dsock;

typedef struct serv_dsock {
  struct sockaddr_un servaddr;
  int sockfd;
} serv_dsock;

eth_addr_t hton6(eth_addr_t addr);
eth_addr_t ntoh6(eth_addr_t addr);

void pretty_print_eth_addr(char hwaddr[6], char *out);
char * create_tempfile(void);
void utils_init(void);
uint32_t current_time_in_ms(void);
void create_cli_dsock(char *file_name, cli_dsock *c);
void create_generic_dsock(const char *path, serv_dsock *s);
void create_odr_dsock(serv_dsock *s);
void create_srv_dsock(serv_dsock *s);
struct hwa_info	*get_hw_addrs(void);
struct hwa_info	*Get_hw_addrs(void);
void free_hwa_info(struct hwa_info *);
void prhwaddrs(void);

#endif
