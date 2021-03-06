// -*- mode: c++; c-basic-offset: 2 -*-
#ifndef _RWINDOW_H_
#define _RWINDOW_H_

#include "treap.h"

typedef struct rwindow {
  treap t_rwin;             
  int smallest_expected_seq;  // The oldest missing packet's sequence number
  int rwinsz;                 // The max size of the receiving window as per "clients.in"
  int last_read_seq;          // How far has the consumer thread has read?
  int last_seq_in_stream;     // The last SEQ# (i.e. That of the FIN packet). If -1, then we haven't yet received the FIN packet.
  pthread_mutex_t *mutex;     // The mutex for using the treap

} rwindow;

void rwindow_init(rwindow *rwin, int rwinsz);
packet_t *rwindow_received_packet(rwindow *rwin, packet_t *pkt); 
packet_t *read_packet(rwindow *rwin);
int calc_adv_rwinsz(rwindow *rwin);
BOOL rwindow_received_all(rwindow *rwin);
#endif
