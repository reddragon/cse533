#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>      
#include <net/if.h>           

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};


struct hwa_info	*get_hw_addrs(void);
struct hwa_info	*Get_hw_addrs(void);
void free_hwa_info(struct hwa_info *);
void prhwaddrs(void);

#endif
