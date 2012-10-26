#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "treap.h"

// The sending window.
typedef struct swindow {
    treap swin;
    int oldest_unacked_seq; // The oldest un-acknowledged packet's sequence number
    int num_acks;           // The number of ACK responses for 'oldest_unacked_seq' that we have seen. This is ONLY for ACKs in sequence AFTER we reset 'oldest_unacked_seq'
    int next_ack_seq;       // The net ACK will be tied to 'next_ack_seq'
    int swin_size_max;      // The maximum size of the sending window
} swindow;

// Once 'oldest_unacked_seq' is incremented, we reset 'num_acks' to 0.

// Once 'num_acks' reaches 3, we re-send the packet with sequence
// number 'oldest_unacked_seq', and double RTO.

// Once the timeout for the packet with sequence number
// 'oldest_unacked_seq' is hit, we re-send that packet. We keep doing
// this till the timeout is hit. If the timout is hit > 12 times, we
// abandon the file transfer altogether. Increase RTO by 2x each time
// and squeeze between [1..3].

// Update RTO based on RTT values

// Always tie an ACK(k) for seq (z < k) to the last unACKed seq (z) at
// the server. If we receive an ACK (k <= z) then we DON'T tie it to this
// unACKed packet. Flush everything up to (k-1).

// Never use duplicate ACKs to update the RTO values.
