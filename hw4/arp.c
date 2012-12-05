// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"
#include "api.h"

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
  int             sll_ifindex;
  unsigned short  sll_hatype;
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
  ipaddr_n;   sender_ip_addr;
  eth_addr_n  target_eth_addr;
  ipaddr_n;   target_ip_addr;
} arp_pkt;


vector      addr_pairs;
eth_addr_n  *eth0_hwaddr;
ipaddr_n    *eth0_ipaddr;   
int         pf_sockfd;
int         ds_sockfd;

// This is the protocol number for ARP packets (used in the eth frames)
#define ARP_PROTOCOL 0x8086 
#define ARP_REQUEST  0x1
#define ARP_RESPONSE 0x2

arp_pkt*
create_arp_pkt(uint16_t op) {
  // TODO Fill this
}

eth_frame*
create_arp_request(eth_addr_n dst_addr) {
  eth_frame *ef;
  arp_pkt pkt;
    ef->dst_addr = dst_addr;
  ef->src_addr = ((addr_pair *)vector_at(&addr_pairs, 0))->eth_n;
  ef->protocol = ARP_PROTOCOL;
  ef = MALLOC(eth_frame);   

  arp_pkt.hard_type = 0x1;          // H/W Type is Ethernet 
  arp_pkt.prot_type = 0x800;        // IP Address
  arp_pkt.hard_size = 6;            // Size of the Ethernet Addr
  arp_pkt.prot_size = 4;            // Size of IP Address
  arp_pkt.op        = ARP_REQUEST;  
  memcpy(ef->payload, pkt, sizeof(arp_pkt));
  // TODO Fill up the target IP and other fields
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
  eth0_hwaddr = a->eth_n;
  eth0_ipaddr = a->ip_ascii;
}

void
setup_sockets(void) {
  struct sockaddr_un servaddr;
  
  // Setting up the Domain Socket for ARP<->Tour communication
  servaddr.sun_family = AF_LOCAL;
  servaddr.sun_path   = SRV_SUN_PATH
  
  unlink(servaddr.sun_path);
  ds_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
  Bind(ds_sockfd, (SA *)&servaddr, sizeof(servaddr);

  // Setting up the PF_PACKET Socket for ARP<->ARP communication
  pf_sockfd = Socket(AF_INET, SOCK_RAW, ARP_PROTOCOL);
  // We do not need to Bind() the PF_PACKET socket, because it
  // is a raw socket, and we will do a Sendto(), which will
  // involve telling the kernel which interface we want to use.
}

void
act_on_api_msg(api_msg *msg) {
  // TODO Fill this
}

// Check if this packet was targeted for me
// We can do this by going through the list of address pairs that we have.
void
is_my_pkt(arp_pkt *pkt) {
  addr_pair *a;
  int n;
  n = vector_size(&addr_pairs);
  for (i = 0; i < n; i++) {
    a = (addr_pair *)vector_at(&addr_pairs, i);
    if (a->eth_n == pkt->target_eth_addr) {
      return true;
    }
  }
  return false;  
}

bool
cache_entry_exists(ipaddr_n target_addr) {
  cache_entry *c;
  int n;
  n = vector_size(&cache);
  for (i = 0; i < n; i++) {
    c = (cache_entry *)vector_at(&cache, i);
    if (c->ip_n == target_addr) {
      return true;
    }
  }
  return false;
}

cache_entry *
add_cache_entry(arp_pkt *pkt, struct sockaddr_ll *sa) {
  cache_entry *c = MALLOC(cache_entry);
  c->eth_n  = pkt->sender_eth_addr;
  c->ip_n   = pkt->sender_ip_addr;
  c->sll_ifindex  = sa->sll_ifindex;
  c->sll_hatype   = sa->sll_hatype;
  c->sockfd       = -1;
  return c;
}

cache_entry *
update_cache_entry(arp_pkt *pkt, struct sockaddr_ll *sa) {
  cache_entry *c;
  int n;
  n = vector_size(&cache);
  for (i = 0; i < n; i++) {
    c = (cache_entry *)vector_at(&cache, i);
    if (c->ip_n == pkt->sender_ip_addr) {
      c->ip_n         = pkt->sender_ip_addr;
      c->sll_ifindex  = sa->sll_ifindex;
      c->sll_hatype   = sa->sll_hatype;
      return c;
    }
  }
  return NULL;
}

void
act_on_eth_pkt(eth_frame *ef, struct sockaddr_ll *sa) {
  arp_pkt pkt;
  cache_entry *centry;
  bool my_pkt, centry_exists;
  
  centry = NULL;
  my_pkt = false;
  centry_exists = false;
  
  // Drop the packet if it is not for the protocol that we respect
  if (ef->protocol != ARP_PROTOCOL) {
    INFO("Dropping a packet which has protocol number %x.\n", 
          ef->protocol);
    return;
  }
  mempcy(&pkt, ef->payload, sizeof(pkt));
  
  if (pkt.ident_num != ARP_IDENT_NUM) {
    INFO("Dropping a packet which has identity number %x.\n", 
          ef->ident_num);
    return;
  }

  my_pkt = is_my_pkt(&pkt);
  centry_exists = cache_entry_exists(&pkt);
  // If it is either my packet (then we should add this entry,
  // or update it). Otherwise, if it exists, but the packet is
  // not mine, I will just update the entry if required.
  if (my_pkt) {
    if (centry_exists) {
      centry = update_cache_entry(&pkt);
    } else {
      centry = add_cache_entry(&pkt);
    }
    
    // If we have a connected client with this cache entry, then
    // we need to flush out the address
    if (centry->sockfd > 0) {
      // TODO 
    }
  } if (!my_pkt && centry_exists) {
    update_cache_entry(&pkt);
  }
}

void
listen_on_sockets(void) {
  // TODO Fill this
}

void
arp_setup(void) {
  get_addr_pairs();
  setup_sockets();
  listen_on_sockets();
}

int 
main(int argc, char **argv) {
  assert(sizeof(arp_pkt) == 28);
  arp_setup();
  return 0;
}
