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
} cache_entry;

#define ETHERNET_PAYLOAD_SIZE 120

typedef struct eth_frame {
  eth_addr_n dst_eth_addr;  // Destination Ethernet Address
  eth_addr_n src_eth_addr;  // Source Ethernet Address
  uint16_t protocol;        // Protocol
  char payload[ETHERNET_PAYLOAD_SIZE];       // Payload
} eth_frame;

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
eth_addr_n  broadcast_eth_addr;
int         pf_sockfd;
int         ds_sockfd;

// This is the protocol number for ARP packets (used in the eth frames)
#define ARP_PROTOCOL 0x8086 
#define ARP_REQUEST  0x1
#define ARP_RESPONSE 0x2

void
send_over_ethernet(eth_frame *ef) {
  struct sockaddr_ll sa;
  int i;
  unsigned char mask = 0xff;

  memset(&sa, 0, sizeof(sa));
  sa.sll_family   = PF_PACKET;
  sa.sll_hatype   = ARPHRD_ETHER;
  sa.sll_pkttype  = PACKET_BROADCAST;
  sa.sll_protocol = ef->protocol;
  sa.sll_ifindex  = 0; // FIXME fix this
  sa.sll_halen    = 6;

  for (i = 0; i < 6; ++i) {
    mask &= *(unsigned char*)(ef->dst_eth_addr.addr + i);
  }

  if (mask != 0xff) {
    sa.sll_pkttype = PACKET_OTHERHOST;
  }

  memcpy(sa.sll_addr, ef->dst_eth_addr.addr, 6);
  Sendto(pf_sockfd, (void *)ef, sizeof(eth_frame), 0, (SA *)&sa, sizeof(sa));
  VERBOSE("send_eth_pkt() terminated successfully\n%s", "");
}

eth_frame*
create_arp_request(eth_addr_n target_eth_addr, ipaddr_n target_ip_addr) {
  eth_frame *ef;
  arp_pkt pkt;
  ef = MALLOC(eth_frame);   
  ef->dst_eth_addr  = target_eth_addr;
  ef->src_eth_addr  = *eth0_hwaddr;
  ef->protocol      = ARP_PROTOCOL;

  pkt.hard_type = 0x1;          // H/W Type is Ethernet 
  pkt.prot_type = 0x800;        // IP Address
  pkt.hard_size = 6;            // Size of the Ethernet Addr
  pkt.prot_size = 4;            // Size of IP Address
  pkt.op        = ARP_REQUEST;    
  pkt.sender_eth_addr = *eth0_hwaddr;
  pkt.sender_ip_addr  = *eth0_ipaddr;
  pkt.target_eth_addr = target_eth_addr;
  pkt.target_ip_addr  = target_ip_addr;
  memcpy(ef->payload, &pkt, sizeof(arp_pkt));
  return ef;
}

void
get_addr_pairs(void) {
  struct hwa_info *head, *h;
  addr_pair *a;
  struct sockaddr *sa;
  
  vector_init(&addr_pairs, sizeof(addr_pair));
  head = Get_hw_addrs();
  for (h = head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0")) {
      a = MALLOC(addr_pair);
      memcpy(a->eth_n.addr, h->if_haddr, sizeof(a->eth_n.addr));
      pretty_print_eth_addr(a->eth_n.addr, a->eth_ascii.addr);
      strcpy(a->if_name, h->if_name);
      sa = (SA *)h->ip_addr;
      strcpy(a->ip_ascii.addr, (char *)Sock_ntop_host(sa, sizeof(*sa)));      
      
      INFO("Interface %s (H/W Address: %s, IP Address: %s)\n",
            a->if_name, a->eth_ascii.addr, a->ip_ascii.addr);
      vector_push_back(&addr_pairs, a);
    }
  }
  // Checking if we got atleast one Eth-Addr, IP-Addr pair.
  ASSERT(vector_size(&addr_pairs) > 0);
  // Get the ethernet address and IP address for eth0 (one of its alias)
  a = (addr_pair *)vector_at(&addr_pairs, 0);
  eth0_hwaddr = &a->eth_n;
  eth0_ipaddr = &a->ip_n;
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
  pf_sockfd = Socket(AF_INET, SOCK_RAW, ARP_PROTOCOL);
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
    if (!memcmp(&c->ip_n, &target_addr, sizeof(eth_addr_n))) {
      return c;
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
  cache_entry *c;
  eth_frame *ef;
  c = get_cache_entry(msg->ipaddr_nw);
  if (c == NULL) {
    c = MALLOC(cache_entry);
    c->ip_n         = msg->ipaddr_nw;
    c->ip_a         = msg->ipaddr_a;
    c->sll_ifindex  = msg->sll_ifindex;
    c->sll_hatype   = msg->sll_hatype;
    c->sll_halen    = msg->sll_halen;
    vector_push_back(&cache, c);
    
    INFO("Created an incomplete cache entry for IP Address: %s.\n",
        msg->ipaddr_a.addr);
    
    ef = create_arp_request(broadcast_eth_addr, c->ip_n);  
    send_over_ethernet(ef);
  } else {
    // Fill up the ethernet address of the requested IP address
    msg->eth_addr     = c->eth_n;
    msg->sll_ifindex  = c->sll_ifindex;
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
    if (!memcmp(&a->eth_n, &pkt->target_eth_addr, sizeof(eth_addr_n))) {
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
  cache_entry *c = MALLOC(cache_entry);
  c->eth_n        = pkt->sender_eth_addr;
  c->ip_n         = pkt->sender_ip_addr;
  c->sll_ifindex  = sa->sll_ifindex;
  c->sll_hatype   = sa->sll_hatype;
  c->sll_halen    = sa->sll_halen;
  c->sockfd       = -1;
  return c;
}

cache_entry *
update_cache_entry(arp_pkt *pkt, struct sockaddr_ll *sa) {
  cache_entry *c;
  int n, i;
  n = vector_size(&cache);
  for (i = 0; i < n; i++) {
    c = (cache_entry *)vector_at(&cache, i);
    if (!memcmp(&c->ip_n, &pkt->sender_ip_addr, sizeof(ipaddr_n))) {
      c->ip_n         = pkt->sender_ip_addr;
      c->sll_ifindex  = sa->sll_ifindex;
      c->sll_hatype   = sa->sll_hatype;
      c->sll_halen    = sa->sll_halen;
      return c;
    }
  }
  return NULL;
}

void
act_on_eth_pkt(eth_frame *ef, struct sockaddr_ll *sa) {
  api_msg msg;
  arp_pkt pkt;
  cache_entry *centry;
  bool my_pkt, centry_exists;
  
  centry = NULL;
  my_pkt = FALSE;
  centry_exists = FALSE;
  
  // Drop the packet if it is not for the protocol that we respect
  if (ef->protocol != ARP_PROTOCOL) {
    INFO("Dropping a packet which has protocol number %x.\n", 
          ef->protocol);
    return;
  }
  memcpy(&pkt, ef->payload, sizeof(pkt));
  
  if (pkt.ident_num != ARP_IDENT_NUM) {
    INFO("Dropping a packet which has identity number %x.\n", 
          pkt.ident_num);
    return;
  }

  my_pkt = is_my_pkt(&pkt);
  centry_exists = cache_entry_exists(pkt.target_ip_addr);
  // If it is either my packet (then we should add this entry,
  // or update it). Otherwise, if it exists, but the packet is
  // not mine, I will just update the entry if required.
  if (my_pkt) {
    INFO("Received an ARP request meant for me.\n%s", "");
    if (centry_exists) {
      centry = update_cache_entry(&pkt, sa);
    } else {
      centry = add_cache_entry(&pkt, sa);
    }
    
    // If we have a connected client with this cache entry, then
    // we need to flush out the address
    if (centry->sockfd > 0) {
      msg.eth_addr    = centry->eth_n;
      msg.ipaddr_a    = centry->ip_a; 
      msg.ipaddr_nw   = centry->ip_n;
      msg.sll_ifindex = centry->sll_ifindex;
      msg.sll_hatype  = centry->sll_hatype;
      msg.sll_halen   = centry->sll_halen;  
      Send(centry->sockfd, (void *)&msg, sizeof(msg), 0);
      centry->sockfd = -1;  // Resetting the sockfd 
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
  act_on_api_msg(&m, ds_sockfd, &cliaddr);    
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
  assert(sizeof(arp_pkt) == 32);
  arp_setup();
  listen_on_sockets();
  return 0;
}