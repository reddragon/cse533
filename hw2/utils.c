#include "utils.h"
#include <unp.h>
#include <ctype.h>
#include <sys/time.h>

struct timeval dob; // Date of Birth

void utils_init(void) {
    Gettimeofday(&dob, NULL);
}

// Blatantly copied from: http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
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

void* my_malloc(size_t size) {
    assert(size < 32000);
    void *ptr = calloc(1, size);
    assert(ptr);
    return ptr;
}

uint32_t current_time_in_ms(void) {
    uint32_t ts;
    struct timeval now, diff;

    Gettimeofday(&now, NULL);
    timeval_subtract(&diff, &now, &dob);

    ts = (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
    return ts;
}

void packet_hton(packet_t *out, const packet_t *in) {
    *out = *in;
    out->ack = htonl(in->ack);
    out->seq = htonl(in->seq);
    out->rwinsz = htonl(in->rwinsz);
    out->flags = htons(in->flags);
    out->datalen = htons(in->datalen);
}

void packet_ntoh(packet_t *out, const packet_t *in) {
    *out = *in;
    out->ack = ntohl(in->ack);
    out->seq = ntohl(in->seq);
    out->rwinsz = ntohl(in->rwinsz);
    out->flags = ntohs(in->flags);
    out->datalen = ntohs(in->datalen);
}

char *strip(char *s) {
    char *r = s;
    int len = strlen(s);
    int i, plen = 0, slen = 0;
    char *d = s;
    int prefix = 1, suffix = 1;

    for (i = 0; s[i]; ++i) {
        if (prefix && isspace(s[i])) {
            ++plen;
        } else {
            break;
        }
    }
    for (i = len-1; i >= 0; --i) {
        if (suffix && isspace(s[i])) {
            ++slen;
        } else {
            break;
        }
    }
    for (i = plen; i < len-slen; ++i) {
        *d++ = s[i];
    }
    *d = '\0';
    return r;
}

void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0); /* get current file status flags */
    flags |= O_NONBLOCK;	       /* turn off blocking flag */
    fcntl(fd, F_SETFL, flags);         /* set up non-blocking read */
}

void set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0); /* get current file status flags */
    flags &= ~(O_NONBLOCK);	       /* turn off blocking flag */
    fcntl(fd, F_SETFL, flags);         /* set up non-blocking read */
}

void set_dontroute(int fd) {
    BOOL yes = 1;
    Setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

int
read_cargs(const char *cargs_file, struct client_args *cargs) {
    FILE *fp = fopen(cargs_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not open file\n");
        return 1;
    }
    int r = fscanf(fp, "%s%u%s%u%u%lf%lf", cargs->ip_addr,
                   &cargs->serv_portno,
                   cargs->file_name,
                   &cargs->sw_size,
                   &cargs->rand_seed,
                   &cargs->p,
                   &cargs->mean);
    assert(r == 7);
    return 0;
}

int
read_sargs(const char *sargs_file, struct server_args *sargs) {
    FILE *fp = fopen(sargs_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not open file\n");
        return 1;
    }
    int r = fscanf(fp, "%d%d", &sargs->serv_portno, &sargs->sw_size);
    assert(r == 2);
    return 0;
}

struct sockaddr*
get_subnet_addr(struct sockaddr *addr, struct sockaddr *ntm) {
    struct sockaddr *sa = MALLOC(SA);
    memcpy(sa, addr, sizeof(SA));
    int i = 0;
    for (i = 2; i < 6; i++) {
        sa->sa_data[i] = (addr->sa_data[i] & 0xFF) & (ntm->sa_data[i] & 0xFF);
    }
    return sa;
}

UINT
get_ntm_len(struct sockaddr *ntm) {
    UINT len = 0;
    int i;
    for (i = 2; i < 6 && ((ntm->sa_data[i] & 0xFF) != 0); i++, len++); 
    return len;
}


// We are we assuming network byte order here.
char *
sa_data_str(struct sockaddr *sa) {
    char *str = (char *)calloc(20, sizeof(char));
    assert(str);
    sprintf(str, "%u.%u.%u.%u", 
            sa->sa_data[2] & 0xFF, sa->sa_data[3] & 0xFF, 
            sa->sa_data[4] & 0xFF, sa->sa_data[5] & 0xFF);
    return str;
}

char *
my_sock_ntop(struct sockaddr *sa) {
    char *str = (char *)calloc(40, sizeof(char));
    assert(str);
    strcpy(str, Sock_ntop(sa, sizeof(*sa)));
    return str;
}


struct sockaddr *
inet_pton_sa(const char *ip_addr, UINT portno) {
    struct sockaddr *sa    = MALLOC(struct sockaddr);
    struct sockaddr_in *si = (struct sockaddr_in*)sa;
    si->sin_family = AF_INET;
    si->sin_port = htons(portno);
    inet_pton(AF_INET, ip_addr, &si->sin_addr);
    return sa;
}

struct ifi_info *
get_ifi_info_plus(int family, int doaliases)
{
    struct ifi_info		*ifi, *ifihead, **ifipnext;
    int					sockfd, len, lastlen, flags, myflags, idx = 0, hlen = 0;
    char				*ptr, *buf, lastname[IFNAMSIZ], *cptr, *haddr, *sdlname;
    struct ifconf		ifc;
    struct ifreq		*ifr, ifrcopy;
    struct sockaddr_in	*sinptr;
    struct sockaddr_in6	*sin6ptr;

    sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

    lastlen = 0;
    len = 100 * sizeof(struct ifreq);	/* initial buffer size guess */
    for ( ; ; ) {
        buf = calloc(len, 1);
        assert(buf);
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
    ifihead = NULL;
    ifipnext = &ifihead;
    lastname[0] = 0;
    sdlname = NULL;
    /* end get_ifi_info1 */

    /* include get_ifi_info2 */
    for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
        ifr = (struct ifreq *) ptr;

#ifdef	HAVE_SOCKADDR_SA_LEN
        len = max(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);
#else
        switch (ifr->ifr_addr.sa_family) {
#ifdef	IPV6
        case AF_INET6:	
            len = sizeof(struct sockaddr_in6);
            break;
#endif
        case AF_INET:	
        default:	
            len = sizeof(struct sockaddr);
            break;
        }
#endif	/* HAVE_SOCKADDR_SA_LEN */
        ptr += sizeof(ifr->ifr_name) + len;	/* for next one in buffer */

#ifdef	HAVE_SOCKADDR_DL_STRUCT
        /* assumes that AF_LINK precedes AF_INET or AF_INET6 */
        if (ifr->ifr_addr.sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
            sdlname = ifr->ifr_name;
            idx = sdl->sdl_index;
            haddr = sdl->sdl_data + sdl->sdl_nlen;
            hlen = sdl->sdl_alen;
        }
#endif

        if (ifr->ifr_addr.sa_family != family)
            continue;	/* ignore if not desired address family */

        myflags = 0;
        /*================== cse 533  Assignment 2 modifications ==========================*/
        /* Original code commented out by Manish Oct.2010 in order to obtain network
           masks and broadcast addresses associated with alias IP addresses under Solaris  */
#if 0
        if ( (cptr = strchr(ifr->ifr_name, ':')) != NULL)
            *cptr = 0;		/* replace colon with null */
#endif
        /*=================================================================================*/
        if (strncmp(lastname, ifr->ifr_name, IFNAMSIZ) == 0) {
            if (doaliases == 0)
                continue;	/* already processed this interface */
            myflags = IFI_ALIAS;
        }
        memcpy(lastname, ifr->ifr_name, IFNAMSIZ);

        ifrcopy = *ifr;
        Ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy);
        flags = ifrcopy.ifr_flags;
        if ((flags & IFF_UP) == 0)
            continue;	/* ignore if interface not up */
        /* end get_ifi_info2 */

        /* include get_ifi_info3 */
        ifi = Calloc(1, sizeof(struct ifi_info));
        *ifipnext = ifi;			/* prev points to this new one */
        ifipnext = &ifi->ifi_next;	/* pointer to next one goes here */

        ifi->ifi_flags = flags;		/* IFF_xxx values */
        ifi->ifi_myflags = myflags;	/* IFI_xxx values */
#if defined(SIOCGIFMTU) && defined(HAVE_STRUCT_IFREQ_IFR_MTU)
        Ioctl(sockfd, SIOCGIFMTU, &ifrcopy);
        ifi->ifi_mtu = ifrcopy.ifr_mtu;
#else
        ifi->ifi_mtu = 0;
#endif
        memcpy(ifi->ifi_name, ifr->ifr_name, IFI_NAME);
        ifi->ifi_name[IFI_NAME-1] = '\0';
        /* If the sockaddr_dl is from a different interface, ignore it */
        if (sdlname == NULL || strcmp(sdlname, ifr->ifr_name) != 0)
            idx = hlen = 0;
        ifi->ifi_index = idx;
        ifi->ifi_hlen = hlen;
        if (ifi->ifi_hlen > IFI_HADDR)
            ifi->ifi_hlen = IFI_HADDR;
        if (hlen)
            memcpy(ifi->ifi_haddr, haddr, ifi->ifi_hlen);
        /* end get_ifi_info3 */
        /* include get_ifi_info4 */
        switch (ifr->ifr_addr.sa_family) {
        case AF_INET:
            sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
            ifi->ifi_addr = Calloc(1, sizeof(struct sockaddr_in));
            memcpy(ifi->ifi_addr, sinptr, sizeof(struct sockaddr_in));

#ifdef	SIOCGIFBRDADDR
            if (flags & IFF_BROADCAST) {
                Ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy);
                sinptr = (struct sockaddr_in *) &ifrcopy.ifr_broadaddr;
                ifi->ifi_brdaddr = Calloc(1, sizeof(struct sockaddr_in));
                memcpy(ifi->ifi_brdaddr, sinptr, sizeof(struct sockaddr_in));
            }
#endif

#ifdef	SIOCGIFDSTADDR
            if (flags & IFF_POINTOPOINT) {
                Ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy);
                sinptr = (struct sockaddr_in *) &ifrcopy.ifr_dstaddr;
                ifi->ifi_dstaddr = Calloc(1, sizeof(struct sockaddr_in));
                memcpy(ifi->ifi_dstaddr, sinptr, sizeof(struct sockaddr_in));
            }
#endif

            /*================== cse 533  Assignment 2 modifications ====================*/

#ifdef  SIOCGIFNETMASK
            Ioctl(sockfd, SIOCGIFNETMASK, &ifrcopy);
            sinptr = (struct sockaddr_in *) &ifrcopy.ifr_addr;
            ifi->ifi_ntmaddr = Calloc(1, sizeof(struct sockaddr_in));
            memcpy(ifi->ifi_ntmaddr, sinptr, sizeof(struct sockaddr_in));
#endif

            /*===========================================================================*/

            break;

#ifdef	IPV6
        case AF_INET6:
            sin6ptr = (struct sockaddr_in6 *) &ifr->ifr_addr;
            ifi->ifi_addr = Calloc(1, sizeof(struct sockaddr_in6));
            memcpy(ifi->ifi_addr, sin6ptr, sizeof(struct sockaddr_in6));
#endif

#ifdef	SIOCGIFDSTADDR
            if (flags & IFF_POINTOPOINT) {
                Ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy);
                sin6ptr = (struct sockaddr_in6 *) &ifrcopy.ifr_dstaddr;
#ifdef	IPV6
                ifi->ifi_dstaddr = Calloc(1, sizeof(struct sockaddr_in6));
                memcpy(ifi->ifi_dstaddr, sin6ptr, sizeof(struct sockaddr_in6));
#endif
            }
#endif
            break;

        default:
            break;
        }
    }
    free(buf);
    return(ifihead);	/* pointer to first structure in linked list */
}
/* end get_ifi_info4 */

/* include free_ifi_info_plus */
void
free_ifi_info_plus(struct ifi_info *ifihead)
{
    struct ifi_info	*ifi, *ifinext;

    for (ifi = ifihead; ifi != NULL; ifi = ifinext) {
        if (ifi->ifi_addr != NULL)
            free(ifi->ifi_addr);
        if (ifi->ifi_brdaddr != NULL)
            free(ifi->ifi_brdaddr);
        if (ifi->ifi_dstaddr != NULL)
            free(ifi->ifi_dstaddr);

        /*=========================== cse 533 Assignment 2 modifications ========================*/

        if (ifi->ifi_ntmaddr != NULL)
            free(ifi->ifi_ntmaddr);

        /*=======================================================================================*/

        ifinext = ifi->ifi_next;	/* can't fetch ifi_next after free() */
        free(ifi);					/* the ifi_info{} itself */
    }
}
/* end free_ifi_info_plus */

struct ifi_info *
Get_ifi_info_plus(int family, int doaliases)
{
    struct ifi_info	*ifi;

    if ( (ifi = get_ifi_info_plus(family, doaliases)) == NULL)
        err_quit("get_ifi_info_plus error");
    return(ifi);
}

void
print_ifi_info(struct ifi_info *ifihead) {
    struct ifi_info	*ifi;
    struct sockaddr	*sa;
    u_char		*ptr;
    int		i, family, doaliases;

    for (ifi = ifihead; ifi != NULL; ifi = ifi->ifi_next) {
        printf("%s: ", ifi->ifi_name);
        if (ifi->ifi_index != 0)
            printf("(%d) ", ifi->ifi_index);
        printf("<");
        /* *INDENT-OFF* */
        if (ifi->ifi_flags & IFF_UP)			printf("UP ");
        if (ifi->ifi_flags & IFF_BROADCAST)		printf("BCAST ");
        if (ifi->ifi_flags & IFF_MULTICAST)		printf("MCAST ");
        if (ifi->ifi_flags & IFF_LOOPBACK)		printf("LOOP ");
        if (ifi->ifi_flags & IFF_POINTOPOINT)	printf("P2P ");
        printf(">\n");
        /* *INDENT-ON* */

        if ( (i = ifi->ifi_hlen) > 0) {
            ptr = ifi->ifi_haddr;
            do {
                printf("%s%x", (i == ifi->ifi_hlen) ? "  " : ":", *ptr++);
            } while (--i > 0);
            printf("\n");
        }
        if (ifi->ifi_mtu != 0)
            printf("  MTU: %d\n", ifi->ifi_mtu);

        if ( (sa = ifi->ifi_addr) != NULL)
            printf("  IP addr: %s\n",
                   Sock_ntop_host(sa, sizeof(*sa)));

        /*=================== cse 533 Assignment 2 modifications ======================*/

        if ( (sa = ifi->ifi_ntmaddr) != NULL)
            printf("  network mask: %s\n",
                   Sock_ntop_host(sa, sizeof(*sa)));

        /*=============================================================================*/

        if ( (sa = ifi->ifi_brdaddr) != NULL)
            printf("  broadcast addr: %s\n",
                   Sock_ntop_host(sa, sizeof(*sa)));
        if ( (sa = ifi->ifi_dstaddr) != NULL)
            printf("  destination addr: %s\n",
                   Sock_ntop_host(sa, sizeof(*sa)));
    }
    // We cannot free the ifi pointer here
    // free_ifi_info_plus(ifihead);
}
