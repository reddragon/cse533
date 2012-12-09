// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "api.h"
#include "fdset.h"

// Essentially a pair of Ethernet Address and the IP Address for an iface
typedef struct addr_pair {
  eth_addr_ascii    eth_ascii;
  eth_addr_n        eth_n;
  ipaddr_ascii      ip_ascii;
  ipaddr_n          ip_n;
  char              if_name[10];
} addr_pair;

// ARP Cache Entry
typedef struct cache_entry {
  eth_addr_n      eth_n;
  ipaddr_n        ip_n;
  ipaddr_ascii    ip_a;
  int             sll_ifindex;
  unsigned short  sll_hatype;
  unsigned char   sll_halen;
  int             sockfd;
  bool            incomplete;
} cache_entry;

#define ARP_IDENT_NUM 0x6006
typedef struct arp_pkt {
  uint16_t    ident_num; 
  uint16_t    hard_type;
  uint16_t    prot_type;
  uint8_t     hard_size;
  uint8_t     prot_size;
  uint16_t    op;
  eth_addr_n  sender_eth_addr;
  ipaddr_n    sender_ip_addr;
  eth_addr_n  target_eth_addr;
  ipaddr_n    target_ip_addr;
} arp_pkt;

fdset       fds;
vector      cache;          // The ARP entry cache
vector      addr_pairs;
eth_addr_n  *eth0_hwaddr;
ipaddr_n    *eth0_ipaddr;
int         eth0_ifindex;
eth_addr_n  broadcast_eth_addr;
int         pf_sockfd;
int         ds_sockfd;

// This is the protocol number for ARP packets (used in the eth frames)
#define ARP_PROTOCOL 0x9671
#define ARP_REQUEST  0x1
#define ARP_RESPONSE 0x2

eth_frame*
create_eth_frame(eth_addr_n target_eth_addr, ipaddr_n target_ip_addr,
                   eth_frame *ef, uint16_t op) {
  ipaddr_ascii t_ip, s_ip;
  eth_addr_ascii t_eth, s_eth;

  arp_pkt *pkt = (arp_pkt*)&ef->payload;
  memset(ef, 0, sizeof(ef));
  ef->dst_eth_addr  = target_eth_addr;
  ef->src_eth_addr  = *eth0_hwaddr;
  ef->protocol      = htons(ARP_PROTOCOL);
  
  pkt->ident_num = ARP_IDENT_NUM; // Identity Number
  pkt->hard_type = 0x1;           // H/W Type is Ethernet 
  pkt->prot_type = 0x800;         // IP Address
  pkt->hard_size = 6;             // Size of the Ethernet Addr
  pkt->prot_size = 4;             // Size of IP Address
  pkt->op        = op;    
  pkt->sender_eth_addr = *eth0_hwaddr;
  pkt->sender_ip_addr  = *eth0_ipaddr;
  pkt->target_eth_addr = target_eth_addr;
  pkt->target_ip_addr  = target_ip_addr;
  
  inet_ntop(AF_INET, (void *)&pkt->target_ip_addr, t_ip.addr, sizeof(t_ip.addr));
  inet_ntop(AF_INET, (void *)&pkt->sender_ip_addr, s_ip.addr, sizeof(s_ip.addr));
  
  t_eth = pp_eth(pkt->sender_eth_addr.addr);
  s_eth = pp_eth(pkt->target_eth_addr.addr);
  VERBOSE("[%s :: %s] -> [%s :: %s]\n",
          s_ip.addr,
          t_eth.addr,
          t_ip.addr,
          s_eth.addr);
  return ef;
}

void
get_addr_pairs(void) {
  struct hwa_info *head, *h;
  addr_pair *a;
  struct sockaddr_in *sa;
  
  vector_init(&addr_pairs, sizeof(addr_pair));
  head = Get_hw_addrs();
  for (h = head; h != NULL; h = h->hwa_next) {
    if (!strncmp(h->if_name, "eth0", 4)) {
      cache_entry c;
      a = MALLOC(addr_pair);
      memcpy(a->eth_n.addr, h->if_haddr, sizeof(a->eth_n.addr));
      memcpy(&(a->ip_n), &((struct sockaddr_in*)h->ip_addr)->sin_addr,
             sizeof(struct in_addr));
      a->eth_ascii = pp_eth(a->eth_n.addr);
      strcpy(a->if_name, h->if_name);

      sa = (struct sockaddr_in *)h->ip_addr;
      a->ip_n = sa->sin_addr;
      strcpy(a->ip_ascii.addr, (char *)Sock_ntop_host((SA *)sa, sizeof(*sa)));

      INFO("Interface [%d]%s (H/W Address: %s, IP Address: %s)\n",
           h->if_index, a->if_name, a->eth_ascii.addr, a->ip_ascii.addr);
      vector_push_back(&addr_pairs, a);
      
      c.eth_n = a->eth_n;
      c.ip_n = a->ip_n;
      c.ip_a = a->ip_ascii;
      c.sll_ifindex = h->if_index;
      c.sll_hatype = -1;
      c.sockfd = -1;
      vector_push_back(&cache, &c);

      if (!strcmp(h->if_name, "eth0")) {
        eth0_hwaddr   = &a->eth_n;
        eth0_ipaddr   = &a->ip_n;
        eth0_ifindex  = h->if_index;
      }
    }
  }
  // Checking if we got atleast one Eth-Addr, IP-Addr pair.
  ASSERT(!vector_empty(&addr_pairs));
}

void
setup_sockets(void) {
  struct sockaddr_un servaddr;
  
  // Setting up the Domain Socket for ARP<->Tour communication
  servaddr.sun_family = AF_LOCAL;
  strcpy(servaddr.sun_path, SRV_SUNPATH);
  
  unlink(servaddr.sun_path);
  ds_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
  Bind(ds_sockfd, (SA *)&servaddr, sizeof(servaddr));

  // Setting up the PF_PACKET Socket for ARP<->ARP communication
  pf_sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ARP_PROTOCOL));
  // We do not need to Bind() the PF_PACKET socket, because it
  // is a raw socket, and we will do a Sendto(), which will
  // involve telling the kernel which interface we want to use.
}

cache_entry *
get_cache_entry(ipaddr_n target_addr) {
  cache_entry *c;
  int n, i;
  n = vector_size(&cache);
  for (i = 0; i < n; i++) {
    c = (cache_entry *)vector_at(&cache, i);
    if (c->ip_n.s_addr == target_addr.s_addr) {
      if (c->incomplete == TRUE) {
        vector_erase(&cache, i);
        return NULL;
      } else {
        return c;
      }
    }
  }
  return NULL;
}

// When the ARP module receives a request for a HW address, it:
// 1. Checks if it has the H/W address for the IP address in its cache
//    - If yes, it responds immediately, and closes the socket.
//    - If no, it makes an incomplete entry in the cache, consisting
//      of the api_msg params, and sends an ARP request 

void
act_on_api_msg(api_msg *msg, int sockfd, struct sockaddr_un *cli) {
  cache_entry ce;
  eth_frame ef;
  cache_entry *pce = &ce;
  memset(&ef.payload, 0, sizeof(ef.payload));
  pce = get_cache_entry(msg->ipaddr_nw);
  if (pce == NULL) {
    memset(&ce, 0, sizeof(cache_entry));
    ce.ip_n         = msg->ipaddr_nw;
    Inet_ntop(AF_INET, (void *)&msg->ipaddr_nw,
              ce.ip_a.addr, sizeof(ce.ip_a.addr));
    ce.sll_ifindex  = msg->sll_ifindex;
    ce.sll_hatype   = msg->sll_hatype;
    ce.sll_halen    = msg->sll_halen;
    ce.sockfd       = sockfd;
    ce.incomplete   = TRUE;

    // Add to cache.
    vector_push_back(&cache, &ce);

    INFO("Created an incomplete cache entry for IP Address: %s.\n",
         ce.ip_a.addr);
    VERBOSE("sockfd of the new entry: %d.\n", ce.sockfd);

    create_eth_frame(broadcast_eth_addr, ce.ip_n, &ef, ARP_REQUEST);
    send_over_ethernet(pf_sockfd, &ef, eth0_ifindex);
  } else {
    VERBOSE("The tour process requested for the address of IP Address: %s, which was served from the cache.\n",
      pce->ip_a.addr);
    // Fill up the ethernet address of the requested IP address
    msg->eth_addr     = pce->eth_n;
    msg->sll_ifindex  = pce->sll_ifindex;
    Send(sockfd, (void *)msg, sizeof(*msg), 0);
    close(sockfd);
  }
}

// Check if this packet was targeted for me
// We can do this by going through the list of address pairs that we have.
bool
is_my_pkt(arp_pkt *pkt) {
  addr_pair *a;
  int n, i;
  n = vector_size(&addr_pairs);
  for (i = 0; i < n; i++) {
    a = (addr_pair *)vector_at(&addr_pairs, i);
    if (!memcmp(&a->ip_n, &pkt->target_ip_addr, sizeof(ipaddr_n))) {
      return TRUE;
    }
  }
  return FALSE;  
}

bool
cache_entry_exists(ipaddr_n target_addr) {
  return (get_cache_entry(target_addr) != NULL);
}

cache_entry *
add_cache_entry(arp_pkt *pkt, struct sockaddr_ll *sa) {
  cache_entry ce;
  memset(&ce, 0, sizeof(ce));
  ce.eth_n        = pkt->sender_eth_addr;
  ce.ip_n         = pkt->sender_ip_addr;
  ce.sll_ifindex  = sa->sll_ifindex;
  ce.sll_hatype   = sa->sll_hatype;
  ce.sll_halen    = sa->sll_halen;
  ce.sockfd       = -1;
  ce.incomplete   = FALSE;
  vector_push_back(&cache, &ce);
  return vector_at(&cache, vector_size(&cache) - 1);
}

cache_entry *
update_cache_entry(arp_pkt *pkt, struct sockaddr_ll *sa) {
  cache_entry *c;
  int n, i;
  n = vector_size(&cache);
  for (i = 0; i < n; i++) {
    c = (cache_entry *)vector_at(&cache, i);
    if (c->ip_n.s_addr == pkt->sender_ip_addr.s_addr) {
      c->eth_n        = pkt->sender_eth_addr;
      c->ip_n         = pkt->sender_ip_addr;
      c->sll_ifindex  = sa->sll_ifindex;
      c->sll_hatype   = sa->sll_hatype;
      c->sll_halen    = sa->sll_halen;
      c->incomplete   = FALSE;
      return c;
    }
  }
  ASSERT(FALSE);
}

void
act_on_eth_pkt(eth_frame *ef, struct sockaddr_ll *sa) {
  api_msg msg;
  arp_pkt pkt;
  eth_frame outgoing_ef;
  eth_addr_ascii target_addr;
  cache_entry *centry;
  char ipaddr_buf[30];
  bool my_pkt, centry_exists;
  
  centry = NULL;
  my_pkt = FALSE;
  centry_exists = FALSE;
  memset(&msg, 0, sizeof(msg));
  
  // Drop the packet if it is not for the protocol that we respect
  if (ef->protocol != htons(ARP_PROTOCOL)) {
    INFO("Dropping a packet which has protocol number %x.\n", 
         ntohs(ef->protocol));
    return;
  }
  memcpy(&pkt, ef->payload, sizeof(pkt));
  
  if (pkt.ident_num != ARP_IDENT_NUM) {
    INFO("Dropping a packet which has identity number %x.\n", 
          pkt.ident_num);
    return;
  }
  
  pp_ip(pkt.target_ip_addr, ipaddr_buf, sizeof(ipaddr_buf));
  my_pkt = is_my_pkt(&pkt);
  centry_exists = cache_entry_exists(pkt.sender_ip_addr);
  // If it is either my packet (then we should add this entry,
  // or update it). Otherwise, if it exists, but the packet is
  // not mine, I will just update the entry if required.
  if (my_pkt) {
    INFO("Received an ARP %s meant for me.\n",
      ((pkt.op == ARP_REQUEST ? "request" :
        (pkt.op == ARP_RESPONSE ? "response" : "<unknown>"))));
    if (centry_exists) {
      centry = update_cache_entry(&pkt, sa);
    } else {
      centry = add_cache_entry(&pkt, sa);
    }
    
    // If we have a connected client with this cache entry, then
    // we need to flush out the address
    if (centry->sockfd > 0) {
      target_addr = pp_eth(centry->eth_n.addr);
      VERBOSE("We have a connection which was waiting on the ethernet address of IP Address %s, which is for ethernet address: %s.\n", 
      ipaddr_buf, target_addr.addr);
      VERBOSE("centry->sockfd: %d.\n", centry->sockfd);
      
      msg.eth_addr    = centry->eth_n;
      msg.ipaddr_nw   = centry->ip_n;
      msg.sll_ifindex = centry->sll_ifindex;
      msg.sll_hatype  = centry->sll_hatype;
      msg.sll_halen   = centry->sll_halen;  
      Send(centry->sockfd, (void *)&msg, sizeof(msg), 0);
      centry->sockfd = -1;  // Resetting the sockfd 
    }
    
    if (pkt.op == ARP_REQUEST) {
      VERBOSE("Preparing the outgoing ethernet frame for IP Address: %s\n",
          ipaddr_buf);
      create_eth_frame(pkt.sender_eth_addr, pkt.sender_ip_addr, &outgoing_ef, ARP_RESPONSE);
      send_over_ethernet(pf_sockfd, &outgoing_ef, sa->sll_ifindex);
    }
  } if (!my_pkt && centry_exists) {
    update_cache_entry(&pkt, sa);
  }
}

void
on_pf_recv(void *o) {
 int r;
 struct sockaddr_ll sa;
 socklen_t addrlen = sizeof(sa);
 eth_frame frame;
 memset(&frame, 0, sizeof(frame));
 r = recvfrom(pf_sockfd, &frame, sizeof(frame), 0, (SA*)&sa, &addrlen);
 VERBOSE("Received an eth_frame of size %d\n", r);
 if (r < 0 && errno == EINTR) {
   VERBOSE("recvfrom got EINTR%s\n", "");
   return;
 }
 if (r < 0) {
   perror("recvfrom");
   exit(1);
 }
 assert_ge(r, 64);
 // memcpy(sa.if_haddr, frame.src_eth_addr, sizeof(sa.if_haddr));
 act_on_eth_pkt(&frame, &sa);
}

void
on_pf_error(void *o) {
  INFO("Error while receiving from the PF_PACKET Socket.\n%s", "");
}

void
on_ud_recv(void *o) {
  struct sockaddr_un cliaddr;
  socklen_t clilen;
  api_msg m;
  int c_sockfd;

  clilen = sizeof(cliaddr);
  memset(&cliaddr, 0, sizeof(cliaddr));
  memset(&m, 0, sizeof(m));
  c_sockfd = Accept(ds_sockfd, (SA*)&cliaddr, &clilen);

  Recv(c_sockfd, (char*)&m, sizeof(api_msg), 0);
  INFO("Received a message from the Tour process.\n%s", "");
  act_on_api_msg(&m, c_sockfd, &cliaddr);    
}

void
on_ud_error(void *o) {
  INFO("Error while receiving from the Domain Socket.\n%s", "");
}

void
on_timeout(void *o) {
  INFO("Timed out.\n%s", "");
}

void
listen_on_sockets(void) {
  int r;
  struct timeval timeout;
  timeout.tv_sec = 10; // FIXME when we know better
  timeout.tv_usec = 0;
  
  // Do a listen() on the Domain Socket
  Listen(ds_sockfd, LISTENQ);

  VERBOSE("Starting to listen on the sockets.\n%s", "");
  fdset_init(&fds, timeout, NULL);
  fdset_add(&fds, &fds.rev,  pf_sockfd, &pf_sockfd, on_pf_recv);
  fdset_add(&fds, &fds.exev, pf_sockfd, &pf_sockfd, on_pf_error);

  fdset_add(&fds, &fds.rev,  ds_sockfd, &ds_sockfd, on_ud_recv);
  fdset_add(&fds, &fds.exev, ds_sockfd, &ds_sockfd, on_ud_error);

  r = fdset_poll(&fds, &timeout, on_timeout);
  if (r < 0) {
    perror("select");
    ASSERT(errno != EINTR);
    exit(1);
  }
}

void
arp_setup(void) {
  utils_init();
  vector_init(&cache, sizeof(cache_entry));
  memset(broadcast_eth_addr.addr, 0xff, sizeof(broadcast_eth_addr.addr));
  get_addr_pairs();
  setup_sockets();
}

int 
main(int argc, char **argv) {
  // TODO 
  // The size of arp_pkt should be 30.
  // 2 + 2 + 2 + 1 + 1 + 6 + 4 + 6 + 4 = 30
  // However, it seems alignment is at play.

  assert_eq(OFFSETOF(eth_frame, src_eth_addr), 6);
  assert_eq(OFFSETOF(eth_frame, protocol), 12);
  assert_eq(sizeof(arp_pkt), 30);

  arp_setup();
  listen_on_sockets();
  return 0;
}
