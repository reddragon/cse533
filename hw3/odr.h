#ifndef _ODR_H_
#define _ODR_H_

#include "api.h" // For the api_msg flags
#include "vector.h"

uint32_t staleness;
// TODO Define ethernet_frame Type macros here
// TODO Choose a type for ODR packets

typedef struct eth_frame {
  // TODO Fill this up here
  char src_eth_addr[6];
  char dst_eth_addr[6];
  // Protocol?
  // Type (2 bytes) ?
  // Payload (upto 1518 - (6+6+2) - 4 bytes) ?
} eth_frame;

// TODO How do we figure out what is the length of the 
// payload?

// TODO This needs to be filled correctly
typedef struct odr_tentry {
  char *dest_sun_path;    // sun_path of the destination
  uint16_t iface_idx;     // The interface index through which we reach the next hop
  char next_hop[6];       // The ethernet address of the next hop
  uint16_t nhops_to_dest; // Number of hops to destination
  uint32_t timestamp_ms;  // Instead of having a TTL, we keep this
} odr_tentry;

// This will be a part of a vector of b_id, which will hold what
// is the last used id for each dest_sun_path
typedef struct b_id {
  char *dest_sun_path;    // sun_path of the destination
  uint32_t last_id;       // The last used broadcast id
} b_id;

typedef enum odr_pkt_type {
  RREQ = 0,
  RREP = 1,
  DATA = 2
} odr_pkt_type;

typedef struct odr_pkt {
  odr_pkt_type ptype;     // Type of the ODR packet
  uint32_t broadcast_id;  // Broadcast ID of the packet    
} odr_pkt;

// Checks if the entry is stale now
void is_stale_entry(odr_tentry *t);
#endif
