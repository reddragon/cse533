// -*- tab-width: 2; c-basic-offset: 2 -*-
#ifndef _ODR_H_
#define _ODR_H_

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdint.h>

#define ODR_PROTOCOL  0x8899 // This was not present in if_ether.h
#define MAX_HOP_COUNT 16

#include "api.h" // For the api_msg flags
#include "vector.h"

uint32_t staleness;
// TODO Define ethernet_frame Type macros here
// TODO Choose a type for ODR packets

typedef struct eth_frame {
  // TODO Fill this up here
  char src_eth_addr[6];   // Source Ethernet Address
  char dst_eth_addr[6];   // Destination Ethernet Address
  uint16_t protocol;      // Protocol
  char payload[1400];     // Payload
} eth_frame;

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
  vector pkt_queue;             // Packet Queue for this Client
  BOOL is_blocked_on_recv;      // Is this client expecting to receive a packet?
} cli_entry;

typedef enum odr_pkt_type {
  RREQ = 0,
  RREP = 1,
  DATA = 2  // Application Payload
} odr_pkt_type;

#define ODR_MSG_SZ 256
typedef struct odr_pkt {
  odr_pkt_type type;      // Type of the ODR packet
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

// Checks if the entry is stale now
BOOL is_stale_entry(route_entry *e);
cli_entry * add_cli_entry(struct sockaddr_un *cliaddr);
cli_entry * get_cli_entry(struct sockaddr_un *cliaddr);
route_entry *get_route_entry(odr_pkt *p);
BOOL is_stale_entry(route_entry *e);

void odr_route_message(odr_pkt *pkt);
void odr_deliver_message_to_client(odr_pkt *pkt);

void update_routing_table(odr_pkt *pkt, struct sockaddr_ll *from);
BOOL should_process_packet(odr_pkt *pkt);
void process_dsock_requests(api_msg *m, cli_entry *c);
void process_eth_pkt(eth_frame *frame, struct sockaddr_ll *sa);
void odr_loop(void);
void on_odr_exit(void);

void on_pf_recv(void *opaque);
void on_pf_error(void *opaque);
void on_ud_recv(void *opaque);
void on_ud_error(void *opaque);

void send_eth_pkt(eth_frame *ef, int iface_idx);

#endif
