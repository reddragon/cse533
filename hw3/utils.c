// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

struct timeval dob; // Date of Birth

void
utils_init(void) {
  Gettimeofday(&dob, NULL);
}

void pretty_print_eth_addr(char hwaddr[6], char *out) {
  char *ptr;
  int i;

  ptr = hwaddr;
  i = IF_HADDR;

  do {
    out += sprintf(out, "%.2x%s", *ptr++ & 0xff, (i == 1) ? "" : ":");
  } while (--i > 0);
}

void* my_malloc(size_t size) {
    // assert(size < 2 * 1048676); // 2MiB
    void *ptr = calloc(1, size);
    ASSERT(ptr);
    return ptr;
}

char *hostname_to_ip_address(const char *hostname, char *ip) {
  struct hostent *he = gethostbyname(hostname);
  struct in_addr **ina;

  if (!he) {
    VERBOSE("Invalid hostname/IP Address '%s'\n", hostname);
    return NULL;
  }

  for (ina = (struct in_addr**)he->h_addr_list; *ina; ++ina) {
    char *addr = inet_ntoa(**ina);
    strcpy(ip, addr);
    return ip;
  }
  return NULL;
}

char *ip_address_to_hostname(const char *ip, char *hostname) {
  struct hostent *he_name;
  struct in_addr ia;
  int r;
  r = inet_pton(AF_INET, ip, &ia);
  if (r != 1) {
    VERBOSE("Invalid IP address: %s\n", ip);
    return NULL;
  }
  he_name = gethostbyaddr(&ia, sizeof(ia), AF_INET);
  if (he_name) {
    strcpy(hostname, he_name->h_name);
    return hostname;
  }
  VERBOSE("Could not perform IP to hostname lookup for IP address: %s\n", ip);
  return NULL;
}

int
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
  /* Perform the carry for the later subtraction by updating y. */
  int nsec;
  if (x->tv_usec < y->tv_usec) {
    nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

eth_addr_t hton6(eth_addr_t addr) {
  return addr;
#if 0
  eth_addr_t ret;
  int i;
  for (i = 0; i < 6; ++i) {
    ret.eth_addr[i] = addr.eth_addr[5-i];
  }
  return ret;
#endif
}

eth_addr_t ntoh6(eth_addr_t addr) {
  return hton6(addr);
}

uint32_t 
current_time_in_ms(void) {
  uint32_t ts;
  struct timeval now, diff;

  Gettimeofday(&now, NULL);
  timeval_subtract(&diff, &now, &dob);

  ts = (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
  return ts;
}

char *
create_tempfile(void) {
  int r, fd;
  char *file_name;
  r = mkdir("/tmp/dynamic_duo/", 0755);
  assert(r == 0 || (r == -1 && errno == EEXIST));
  file_name = NMALLOC(char, 64);
  strcpy(file_name, "/tmp/dynamic_duo/dsockXXXXXX");
  fd = mkstemp(file_name);
  assert(fd > 0);
  return file_name;
}

void
create_cli_dsock(char *file_name, cli_dsock *c) {
  struct sockaddr_un servaddr;

  ASSERT(c);

  // We need to unlink (before calling Socket()) because mkstemp will
  // create the file for us
  unlink(file_name); 

  c->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  bzero(&c->cliaddr, sizeof(c->cliaddr));
  c->cliaddr.sun_family = AF_LOCAL;

  strcpy(c->cliaddr.sun_path, file_name);
  Bind(c->sockfd, (SA *) &c->cliaddr, sizeof(c->cliaddr));

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sun_family = AF_LOCAL;
  strcpy(servaddr.sun_path, ODR_DGPATH);
  
  // This is required since unlike normal TCP/UDP sockets, the
  // kernel does not create an ephemeral port for us.
  connect(c->sockfd, (SA*)&(servaddr), sizeof(servaddr));
}

void
create_generic_dsock(const char *path, serv_dsock *s) {
  ASSERT(s);
  unlink(path);
  s->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  bzero(&s->servaddr, sizeof(s->servaddr));
  s->servaddr.sun_family = AF_LOCAL;
  strcpy(s->servaddr.sun_path, path);

  Bind(s->sockfd, (SA *) &s->servaddr, sizeof(s->servaddr));
  VERBOSE("Successfully bound to the AF_LOCAL socket at path: %s\n", path);
}

void
create_odr_dsock(serv_dsock *s) {
  create_generic_dsock(ODR_DGPATH, s);
}

void
create_srv_dsock(serv_dsock *s) {
  create_generic_dsock(SRV_DGPATH, s);
}

struct hwa_info *
get_hw_addrs(void)
{
	struct hwa_info	*hwa, *hwahead, **hwapnext;
	int		sockfd, len, lastlen, alias;
	char		*ptr, *buf, lastname[IF_NAME], *cptr;
	struct ifconf	ifc;
	struct ifreq	*ifr, ifrcopy;
	struct sockaddr	*sinptr;

	sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);	/* initial buffer size guess */
	for ( ; ; ) {
		buf = (char*) Malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0)
				err_sys("ioctl error");
		} else {
			if (ifc.ifc_len == lastlen)
				break;		/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		free(buf);
	}
	hwahead = NULL;
	hwapnext = &hwahead;
	lastname[0] = 0;
	for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
		ifr = (struct ifreq *) ptr;
		len = sizeof(struct sockaddr);
		ptr += sizeof(ifr->ifr_name) + len;	/* for next one in buffer */
		alias = 0; 
		hwa = (struct hwa_info *) Calloc(1, sizeof(struct hwa_info));
		memcpy(hwa->if_name, ifr->ifr_name, IF_NAME);		/* interface name */
		hwa->if_name[IF_NAME-1] = '\0';
				/* start to check if alias address */
		if ( (cptr = (char *) strchr(ifr->ifr_name, ':')) != NULL)
			*cptr = 0;		/* replace colon will null */
		if (strncmp(lastname, ifr->ifr_name, IF_NAME) == 0) {
			alias = IP_ALIAS;
		}
		memcpy(lastname, ifr->ifr_name, IF_NAME);
		ifrcopy = *ifr;
		*hwapnext = hwa;		/* prev points to this new one */
		hwapnext = &hwa->hwa_next;	/* pointer to next one goes here */

		hwa->ip_alias = alias;		/* alias IP address flag: 0 if no; 1 if yes */
                sinptr = &ifr->ifr_addr;
		hwa->ip_addr = (struct sockaddr *) Calloc(1, sizeof(struct sockaddr));
	        memcpy(hwa->ip_addr, sinptr, sizeof(struct sockaddr));	/* IP address */
		Ioctl(sockfd, SIOCGIFHWADDR, &ifrcopy);	/* get hw address */
		memcpy(hwa->if_haddr, ifrcopy.ifr_hwaddr.sa_data, IF_HADDR);
		Ioctl(sockfd, SIOCGIFINDEX, &ifrcopy);	/* get interface index */
		memcpy(&hwa->if_index, &ifrcopy.ifr_ifindex, sizeof(int));
	}
	free(buf);
	return(hwahead);	/* pointer to first structure in linked list */
}

void
free_hwa_info(struct hwa_info *hwahead)
{
	struct hwa_info	*hwa, *hwanext;

	for (hwa = hwahead; hwa != NULL; hwa = hwanext) {
		free(hwa->ip_addr);
		hwanext = hwa->hwa_next;	/* can't fetch hwa_next after free() */
		free(hwa);			/* the hwa_info{} itself */
	}
}
/* end free_hwa_info */

struct hwa_info *
Get_hw_addrs(void)
{
	struct hwa_info	*hwa;

	if ( (hwa = get_hw_addrs()) == NULL)
		err_quit("get_hw_addrs error");
	return(hwa);
}

void
prhwaddrs(void) {
  struct hwa_info *hwa, *hwahead;
  struct sockaddr *sa;
  char   *ptr;
  int    i, prflag;

  printf("\n");

  for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {

    printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

    if ( (sa = hwa->ip_addr) != NULL)
      printf("\tIP addr = %s\n", (char *)Sock_ntop_host(sa, sizeof(*sa)));

    prflag = 0;
    i = 0;
    do {
      if (hwa->if_haddr[i] != '\0') {
        prflag = 1;
        break;
      }
    } while (++i < IF_HADDR);

    if (prflag) {
      printf("\tHW addr = ");
      ptr = hwa->if_haddr;
      i = IF_HADDR;
      do {
        printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
      } while (--i > 0);
      printf("\n");
    }

    printf("\tinterface index = %d\n\n", hwa->if_index);
  }

  free_hwa_info(hwahead);
}
