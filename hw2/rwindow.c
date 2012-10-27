#include "utils.h"
#include "treap.h"
#include "rwindow.h"

// Initialize the receiving window for the client
void rwindow_init(rwindow *rwin, int rwinsz) {
  treap_init(&rwin->t_rwin);
  rwin->smallest_expected_seq = 0; 
  rwin->rwinsz = rwinsz;
  rwin->last_read_seq = -1;
}

// 1. If the packet has the flag FLAG_SYN, then handle it separately
// and the first sequence number for the actual data is 1.

// 2. We should close the socket after an ACK is sent for the FIN

// 3. If we receive a packet, which was already received, discard
// it, and return an appropriate ACK

// Returns a well-formed acknowledgement packet 
packet_t *rwindow_received_packet(packet_t *pkt, rwindow *rwin) { 
  // TODO
  // Discard packet if we do not have space on the receiving
  // window.

  // We will only use the header for the ACK packet
  packet_t *ack_pkt = (packet_t *) malloc(PACKET_HEADER_SZ);
  
  // Check if this is a duplicate packet, which was already
  // received. We can find this out in two ways:
  // 1. Either the packet already exists in the treap. In this
  //   case, it is clearly a duplicate
  // 2. Or, the packet's seq is lesser than the smallest_expected_seq.
  //   In this case, we would have definitely read this packet from
  //   the sliding window, since (1) is not true.
  
  // TODO: Mutex lock here
  // If neither (1), nor (2) is true. Which means, we have
  // a new packet in our hands.
  if (!((treap_find(&rwin->t_rwin, pkt->seq)) || 
      (pkt->seq < rwin->smallest_expected_seq))) {
    // TODO
    // We assume that the server respects the sliding window
    // size that we piggyback on the ACK.
    // Insert the packet into the treap
    treap_insert(&rwin->t_rwin, pkt->seq, (void *)pkt);

    while (!treap_find(&rwin->t_rwin, rwin->smallest_expected_seq)) {
      rwin->smallest_expected_seq++;
    }
  }
  // TODO Mutex unlock here
  
  // Marshalling the acknowledgment packet
  ack_pkt->seq = 0;
  ack_pkt->ack = rwin->smallest_expected_seq;
  ack_pkt->flags = FLAG_ACK;
  ack_pkt->rwinsz = rwin->rwinsz - treap_size(&rwin->t_rwin);
  return ack_pkt;
}

// Check if the next packet that we expect is here
packet_t *read_packet(rwindow *rwin) {
  int next_seq = rwin->last_read_seq + 1;
  packet_t *pkt = treap_find(&rwin->t_rwin, next_seq);
  if (pkt == NULL) {
    return NULL;
  }
  
  // TODO: lock mutex here
  treap_delete(&rwin->t_rwin, next_seq);
  rwin->last_read_seq = rwin->last_read_seq + 1;
  // TODO: unlock mutex here
  return pkt;
}


