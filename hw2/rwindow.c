#include "utils.h"
#include "treap.h"
#include "rwindow.h"

// Initialize the receiving window for the client
void rwindow_init(rwindow *rwin, int rwinsz) {
  treap_init(&rwin->t_rwin);
  // TODO Fix. The smallest packet to expect should be 2.
  rwin->smallest_expected_seq = 1; 
  rwin->rwinsz = rwinsz;
  rwin->last_read_seq = -1;
  rwin->mutex = MALLOC(pthread_mutex_t);
  pthread_mutex_init(rwin->mutex, NULL);
}

// 1. If the packet has the flag FLAG_SYN, then handle it separately
// and the first sequence number for the actual data is 1.

// 2. We should close the socket after an ACK is sent for the FIN

// 3. If we receive a packet, which was already received, discard
// it, and return an appropriate ACK

// Returns a well-formed acknowledgement packet 
packet_t *rwindow_received_packet(rwindow *rwin, packet_t *opkt) { 
  // TODO
  // Do not discard packet if we do not have space on the receiving
  // window. Reply with the next expected seq.

  if (rwin->rwinsz == treap_sz) {
    pthread_mutex_unlock(rwin->mutex);

    // This is basically saying to the server:
    // "I don't know what you are sending me, but I want
    //  ack_pkt->ack, and I don't have space yet"
    ack_pkt->rwinsz = 0;
    ack_pkt->ack = rwin->smallest_expected_seq;
    ack_pkt->flags = FLAG_ACK;
    ack_pkt->datalen = 0;
    return ack_pkt;
  }
  

  pkt = MALLOC(packet_t);
  memcpy(pkt, opkt, sizeof(packet_t));
  
  // Check if this is a duplicate packet, which was already
  // received. We can find this out in two ways:
  // 1. Either the packet already exists in the treap. In this
  //   case, it is clearly a duplicate
  // 2. Or, the packet's seq is lesser than the smallest_expected_seq.
  //   In this case, we would have definitely read this packet from
  //   the sliding window, since (1) is not true.

  // If neither (1), nor (2) is true. Which means, we have
  // a new packet in our hands.
  if (!((treap_find(&rwin->t_rwin, pkt->seq)) || 
      (pkt->seq < rwin->smallest_expected_seq))) {
    // TODO
    // We assume that the server respects the sliding window
    // size that we piggyback on the ACK.
    // Insert the packet into the treap
#ifdef DEBUG
    fprintf(stderr, "Inserting into treap the packet %d with datalen %d and flags %x\n", pkt->seq, pkt->datalen, pkt->flags);
#endif
    treap_insert(&rwin->t_rwin, pkt->seq, (void *)pkt);
    
    int *seq = &rwin->smallest_expected_seq;
    while (treap_find(&rwin->t_rwin, *seq)) {
      *seq = *seq + 1;
    } 
  } else {
#ifdef DEBUG
      fprintf(stderr, "The packet %d was already in the treap\n", pkt->seq);
#endif
  }
  treap_sz = treap_size(&rwin->t_rwin);
  pthread_mutex_unlock(rwin->mutex);
  
  // Marshalling the acknowledgment packet
  ack_pkt->seq = 0;
  ack_pkt->ack = rwin->smallest_expected_seq;
  ack_pkt->flags = FLAG_ACK;
  ack_pkt->rwinsz = rwin->rwinsz - treap_sz;
  // This is only for the debug mode
  ack_pkt->datalen = 0;
  return ack_pkt;
}

// Check if the next packet that we expect is here
packet_t *read_packet(rwindow *rwin) {
  pthread_mutex_lock(rwin->mutex);
  int next_seq = rwin->last_read_seq + 1;
  
  treap_node *tn = treap_find(&(rwin->t_rwin), next_seq);
  if (tn == NULL) {
    pthread_mutex_unlock(rwin->mutex);
    return NULL;
  }
  
  treap_delete(&rwin->t_rwin, next_seq);
  pthread_mutex_unlock(rwin->mutex);
  
  rwin->last_read_seq = rwin->last_read_seq + 1;
  return (packet_t *)(tn->data);
}


