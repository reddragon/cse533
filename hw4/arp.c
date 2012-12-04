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

vector addr_pairs;

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
}

void
arp_setup(void) {
  get_addr_pairs();
}

int 
main(int argc, char **argv) {
  arp_setup();
  return 0;
}
