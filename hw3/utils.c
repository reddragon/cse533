// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include <sys/stat.h>
#include <sys/types.h>

struct timeval dob; // Date of Birth

void 
utils_init(void) {
  Gettimeofday(&dob, NULL);
}

int 
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
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
  int r = mkdir("/tmp/dynamic_duo/", 0755);
  assert(r == 0 || (r == -1 && errno == EEXIST));
  char *file_name = NMALLOC(char, 64);
  strcpy(file_name, "/tmp/dynamic_duo/dsockXXXXXX");
  int fd = mkstemp(file_name);
  assert(fd > 0);
  return file_name;
}

void
create_cli_dsock(char *file_name, cli_dsock *c) {
  if (c == NULL) {
    c = MALLOC(cli_dsock);
  }
  c->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  bzero(&c->cliaddr, sizeof(c->cliaddr));
  c->cliaddr.sun_family = AF_LOCAL;

  // We need to unlink because mkstemp will create the file for us
  unlink(file_name); 
  strcpy(c->cliaddr.sun_path, file_name);
  Bind(c->sockfd, (SA *) &c->cliaddr, sizeof(c->cliaddr));
  
  bzero(&c->servaddr, sizeof(c->servaddr));
  c->servaddr.sun_family = AF_LOCAL;
  strcpy(c->servaddr.sun_path, SRVDGPATH);
  
  // This is required since unlike normal TCP/UDP sockets, the
  // kernel does not create an ephemeral port for us.
  connect(c->sockfd, (SA *) &(c->servaddr), sizeof(c->servaddr));
}

void
create_serv_dsock(serv_dsock *s) {
  if (s == NULL) {
    s = MALLOC(serv_dsock);
  }
  s->sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);
  unlink(SRVDGPATH);
  bzero(&s->servaddr, sizeof(s->servaddr));
  s->servaddr.sun_family = AF_LOCAL;
  strcpy(s->servaddr.sun_path, SRVDGPATH);
  
  Bind(s->sockfd, (SA *) &s->servaddr, sizeof(s->servaddr));
  VERBOSE("Successfully bound to the socket\n%s", "");
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
      printf("\t\tIP addr = %s\n", (char *)Sock_ntop_host(sa, sizeof(*sa)));

    prflag = 0;
    i = 0;
    do {
      if (hwa->if_haddr[i] != '\0') {
        prflag = 1;
        break;
      }
    } while (++i < IF_HADDR);

    if (prflag) {
      printf("\t\tHW addr = ");
      ptr = hwa->if_haddr;
      i = IF_HADDR;
      do {
        printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
      } while (--i > 0);
    }

    printf("\n\t\tinterface index = %d\n\n", hwa->if_index);
  }

  free_hwa_info(hwahead);
}
