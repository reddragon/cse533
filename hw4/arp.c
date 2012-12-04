// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"

// Essentially a pair of Ethernet Address and the IP Address for an iface
typedef struct addr_pair {
  eth_addr_a  hwaddr_a;
  eth_addr_n  hwaddr_n
  ip_addr_a   ipaddr_a;
  ip_addr_n   ipaddr_n;
  char        if_name[10];
} addr_pair;

vector addr_pairs;

void
get_addr_pairs() {
  struct hwa_info *head, *h;
  addr_pair *a;
  struct sockaddr *sa;

  vector_init(&addr_pairs);
  head = Get_hw_addrs();
  for (h = head; h != NULL; h = h->hwa_next) {
    if (!strcmp(h->if_name, "eth0")) {
      a = MALLOC(addr_pair);
      memcpy(a->hw_addr_n.addr, h->hw_addr, sizeof(a->hw_addr_n.addr));
      pretty_print_eth_addr(a->hw_addr_n.addr, a->hw_addr_n.addr);
      strcpy(a->if_name, h->if_name);
      sa = (SA *)a->ip_addr;
      strcpy(a->ip_addr_a.addr, (char *)Sock_ntop_host(sa));      
      
      INFO("Interface %s (H/W Address: %s, IP Address: %s)\n",
            a->hw_addr_a.addr, a->ip_addr_a.addr);
      vector_push_back(&addr_pairs, a);
    }
  }
}

void
arp_setup() {
  get_addr_pairs();
}

int 
main(int argc, char **argv) {
  arp_setup();
}
