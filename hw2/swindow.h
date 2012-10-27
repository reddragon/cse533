#ifndef SWINDOW_H
#define SWINDOW_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "treap.h"
#include "utils.h"

//                          opaque, buffer, size
typedef int  (*read_more_cb)(void*,  void*,  int);

enum { TX_SUCCESS=0, TX_FAILURE=1 };
//                     status (0->success; 1->failure)
typedef void (*end_cb)(int);

typedef void (*ack_cb)(void*);


typedef struct rtt_info_t {
    // All values are in 'ms'.
    int _8srtt;
    int _8rttvar;
    int _8rto;
} rtt_info_t;

void rtt_info_init(rtt_info_t *rtt);
// Periodically update the RTO values. mRTT is in 'ms'.
void rtt_update(rtt_info_t *rtt, int mRTT);
// Fetch the RTO in 'ms'.
uint32_t rtt_get_RTO(rtt_info_t *rtt);
void rtt_scale_RTO(rtt_info_t *rtt, int factor);

// Struct for packet sent.
typedef struct tx_packet_info {
    uint32_t sent_at_ms;
    packet_t pkt;
} tx_packet_info;

tx_packet_info* make_tx_packet(packet_t *pkt);

// The sending window.
typedef struct swindow {
    treap swin;             // A dictionary holding the in-flight packets
    int fd;                 // The FD of the connected client
    int fd2;                // The FD of the original UDP socket to which the client connected. We use this to send the initial ACK
    struct sockaddr *csa;   // The struct sockaddr of the client. We use this to sendto(2) the port number on fd2
    int oldest_unacked_seq; // The oldest un-acknowledged packet's sequence number
    int num_acks;           // The number of ACK responses for 'oldest_unacked_seq' that we have seen. This is ONLY for ACKs in sequence AFTER we reset 'oldest_unacked_seq'
    int next_seq;           // The seq # of the next packet to be sent
    int swinsz;             // The current size of the sending window
    int rwinsz;             // The current size of the receiver window
    int rbuffsz;            // The size of the buffer at the receiver
    int sbuffsz;            // The size of the buffer at the sender
    int oas_num_time_outs;  // The # of times the packet with seq # 'oldest_unacked_seq' timed out.
    read_more_cb read_some; // Callback to read more data
    end_cb on_end;          // Callback to indicate end of transmission
    ack_cb advanced_ack_cb; // Callback to indicate that the oldest_unacked_seq was updated
    void *opaque;           // Opaque data passed to the read_some callback
    rtt_info_t rtt;
    BOOL isEOF;             // End-Of-File if TRUE
    // Something for a timeout to be used in select(2)
} swindow;

// We can only send as many packets as MIN(swinsz, rwinsz).

// When we receive an ACK, we delete stuff in-order from the treap
// (swin). The number of in-flight packets can be computed as
// treap_size(&swin). If the client reports an rwinsz > the #
// of in-flight packets, we can send those many packets (i.e. the
// difference between the window size and the # of in-flight packets).

// For window probe packets, we squeeze the timeout values in the
// range [5..60]. Window probes are sent indefinitely.

// Once 'oldest_unacked_seq' is incremented, we reset 'num_acks' to 0.

// Once 'num_acks' reaches 3, we re-send the packet with sequence
// number 'oldest_unacked_seq', and double RTO. (verify).

// Once the timeout for the packet with sequence number
// 'oldest_unacked_seq' is hit, we re-send that packet. We keep re-sending
// this packet till the timeout is hit. If the timout is hit > 12 times, we
// abandon the file transfer altogether. Increase RTO by 2x each time
// and squeeze between [1..3] sec.

// Update RTO based on RTT values

// Always tie an ACK(k) for seq (z < k) to the last unACKed seq (z) at
// the server. If we receive an ACK (k <= z) then we DON'T tie it to this
// unACKed packet. Flush everything up to (k-1).

// Never use duplicate ACKs to update the RTO values.

// Do NOT update SRTT/RTO values if a timeout for a packet was
// detected. Only use RTT values for ACKs that are recerived in normal
// operation (i.e. not due to a timeout/re-transmit, etc...).

// Doubled RTO values get carried forward in the next select(2) loop
// as well.

// Using select(2) is a *good* idea.

void swindow_dump(swindow *swin);
void swindow_init(swindow *swin, int fd, int fd2, struct sockaddr *csa,
                  int swinsz, read_more_cb read_some,
                  void *opaque, ack_cb advanced_ack_cb, end_cb on_end);
// This function also updates the receiving buffer and receiving
// window size.
void swindow_received_ACK(swindow *swin, int ack, int rwinsz);
void swindow_received_ACK_real(swindow *swin, int ack, int rwinsz);
// We assume that the packet with SEQ # (seq) is available in swin->swin.
void swindow_transmit_packet(swindow *swin, int seq);
void swindow_timed_out(swindow *swin);

#endif // SWINDOW_H
