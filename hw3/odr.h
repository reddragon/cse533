// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _ODR_H_
#define _ODR_H_

#include <linux/if_arp.h>
#include <sys/socket.h>
#include <stdint.h>
#include "utils.h"

#define ODR_PROTOCOL  0x8899 // This was not present in if_ether.h
#define MAX_HOP_COUNT 16

#include "api.h" // For the api_msg flags
#include "vector.h"

#define ETHERNET_PAYLOAD_SIZE 120

uint32_t staleness;
// TODO Define ethernet_frame Type macros here
// TODO Choose a type for ODR packets

typedef struct eth_frame {
  eth_addr_t dst_eth_addr;  // Destination Ethernet Address
  eth_addr_t src_eth_addr;  // Source Ethernet Address
  uint16_t protocol;        // Protocol
  char payload[ETHERNET_PAYLOAD_SIZE];       // Payload
} eth_frame;

typedef struct bid_entry {
  char src_ip[16];
  uint32_t bid;
} bid_entry;

// TODO How do we figure out what is the length of the 
// payload?

// TODO This needs to be filled correctly
typedef struct route_entry {
  char ip_addr[16];             // The IP address of the machine we are maintaining this entry for. i.e. The IP address of the final destination
  int iface_idx;                // The interface index through which we reach the next hop
  char next_hop[6];             // The ethernet address of the next hop
  uint16_t nhops_to_dest;       // Number of hops to destination
  uint32_t last_updated_at_ms;  // When was this entry updated?
} route_entry;

// This is the entry used to forward messages from the 
// ODR to the client
typedef struct cli_entry {
  struct sockaddr_un *cliaddr;  // The client's sockaddr_un
  uint32_t last_id;             // The last used broadcast id
  uint32_t e_portno;            // Ephemeral port number assigned
} cli_entry;

typedef enum odr_pkt_type {
  PKT_RREQ = 1,
  PKT_RREP = 2,
  PKT_DATA = 3  // Application Payload
} odr_pkt_type;

typedef struct odr_pkt {
  uint16_t type;          // Type of the ODR packet
  uint32_t broadcast_id;  // Broadcast ID of the packet 
  uint8_t hop_count;      // Hop Count of the packet
  char src_ip[20];        // Canonical IP address of the source
  char dst_ip[20];        // Canonical IP address of the destination
  int src_port;           // Source Port Number
  int dst_port;           // Destination Port Number
  uint32_t flags;         // Flags associated with the packet
  uint16_t msg_size;      // The size of the 'msg' field.
  char msg[ODR_MSG_SZ];   // Message to be sent
} odr_pkt;

const char *pkt_type_to_str(enum odr_pkt_type o);
BOOL is_stale_entry(route_entry *e);
BOOL is_my_ip(const char *ip);
cli_entry * add_cli_entry(struct sockaddr_un *cliaddr);
cli_entry * get_cli_entry(struct sockaddr_un *cliaddr);
route_entry *get_route_entry(const char *ip);
void prune_routing_table(const char *ip, int flags);
const char *str_flags(int flags);
void prune_cli_table(void);
BOOL is_stale_entry(route_entry *e);
odr_pkt *create_odr_pkt(api_msg *m, cli_entry *c);
void print_routing_table(void);

void odr_setup(void);
void odr_route_message(odr_pkt *pkt, route_entry *e);

BOOL odr_queue_or_send_rrep(const char *fromip, const char *toip,
                            int flags, int hop_count);
void odr_deliver_message_to_client(odr_pkt *pkt);
void odr_start_route_discovery(odr_pkt *pkt, int except_ifindex, BOOL send_as_me);
void odr_packet_print(odr_pkt *pkt);
void odr_loop(void);

void maybe_flush_queued_data_packets(void);
void act_on_packet(odr_pkt *pkt, struct sockaddr_ll *from,
                   BOOL updated_routing_table);
BOOL update_routing_table(odr_pkt *pkt, struct sockaddr_ll *from);
BOOL should_process_packet(odr_pkt *pkt);
void process_dsock_requests(api_msg *m, cli_entry *c);
void process_eth_pkt(eth_frame *frame, struct sockaddr_ll *sa);
void on_odr_exit(void);

void on_pf_recv(void *opaque);
void on_pf_error(void *opaque);
void on_ud_recv(void *opaque);
void on_ud_error(void *opaque);

void
send_over_ethernet(eth_addr_t from, eth_addr_t to, void *data,
                   int len, int iface_idx);
void send_eth_pkt(eth_frame *ef, int iface_idx);

#endif
