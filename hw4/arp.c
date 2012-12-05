// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include "vector.h"

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
  ipaddr_n    ip_n;
  eth_addr_n  eth_n;
  int         sll_ifindex;
  int         sll_hatype;
  int         sockfd;
} cache_entry;

#define ETHERNET_PAYLOAD_SIZE 120

typedef struct eth_frame {
  eth_addr_n dst_eth_addr;  // Destination Ethernet Address
  eth_addr_n src_eth_addr;  // Source Ethernet Address
  uint16_t protocol;        // Protocol
  char payload[ETHERNET_PAYLOAD_SIZE];       // Payload
} eth_frame;

typedef struct arp_pkt {
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


vector addr_pairs;

// This is the protocol number for ARP packets (used in the eth frames)
#define ARP_PROTOCOL 0x806 

eth_frame*
create_arp_request(eth_addr_n dst_addr) {
  eth_frame *ef;
  arp_pkt pkt;
  ef->dst_addr = dst_addr;
  ef->src_addr = ((addr_pair *)vector_at(&addr_pairs, 0))->eth_n;
  ef->protocol = ARP_PROTOCOL;
  ef = MALLOC(eth_frame); 
  

  memcpy(ef->payload, pkt, sizeof(arp_pkt));

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
}

void
arp_setup(void) {
  get_addr_pairs();
}

int 
main(int argc, char **argv) {
  assert(sizeof(arp_pkt) == 28);
  arp_setup();
  return 0;
}
