#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "treap.h"

typedef int (*read_more_cb)(void*, void*, int);

typedef struct rtt_info {
    // All values are in 'ms'.
    int _8srtt;
    int _8rttvar;
    int _8rto;
} rtt_info;

void rtt_info_init(rtt_info *rtt) {
    rtt->_8srtt = 0;
    rtt->_8rttvar = 750 * 8;
    rtt->_8rto = rtt->_8srtt + rtt->_8rttvar * 4;
}


// Periodically update the RTO values.
void rtt_update(rtt_info *rtt, int mRTT) {
    int _8mRTT = mRTT * 8;
    int _8delta = _8mRTT - rtt->_8srtt;
    rtt->_8srtt += (_8delta / 8);
    rtt->_8rttvar = (3 * (rtt->_8rttvar) + _8delta) / 4;
    rtt->_8rto = rtt->_8srtt + (4 * rtt->_8rttvar);
}

// The sending window.
typedef struct swindow {
    treap swin;
    int oldest_unacked_seq; // The oldest un-acknowledged packet's sequence number
    int num_acks;           // The number of ACK responses for 'oldest_unacked_seq' that we have seen. This is ONLY for ACKs in sequence AFTER we reset 'oldest_unacked_seq'
    int swinsz;             // The maximum size of the sending window
    int rwinsz;             // The current size of the receiver window
    int rbuffsz;            // The size of the buffer are the receiver
    int oas_timed_out;      // 1 if ever a timeout for the 'oldest_unacked_seq' was reported.
    read_more_cb read_some; // Callback to read more data
    void *opaque;           // Opaque data passed to the read_some callback
    rtt_info rtt;
    // Something for a timeout to be used in select(2)
} swindow;

// We can only send as many packets as MIN(swin, rwin).

// When we receive an ACK, we delete stuff in-order from the treap
// (swin). The number of in-flight packets can be computed as
// treap_size(&swin). If the client reports an rwinsz > the #
// of in-flight packets, we can send those many packets (i.e. the
// difference between the window size and the # of in-flight packets).

// For window probe packets, we squeeze the timeout values in the
// range [5..60]. Window probes are sent indefinitely.

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

// Do NOT update SRTT/RTO values if a timeout for a packet was
// detected. Only use RTT values for ACKs that are recerived in normal
// operation (i.e. not due to a timeout/re-transmit, etc...).

// Doubled RTO values get carried forward in the next select(2) loop
// as well.

// Using select(2) is a *good* idea.

void swindow_init(swindow *swin, int swinsz) {
    treap_init(&swin->swin);
    swin->oldest_unacked_seq = 0;
    swin->num_acks           = 0;
    swin->swinsz             = swinsz;
    swin->rwinsz             = 0;
    swin->rbuffsz            = 0;
    swin->oas_timed_out      = 0;
    swin->read_some          = NULL;
    swin->opaque             = 0;
    rtt_info_init(&swin->rtt);
}

// This functions also updates the receiving buffer and receiving
// window size.
void swindow_received_ACK(swindow *swin, int ack) {
    int effwinsz;           // The effective window size
    // effwinsz = intmin(

    if (ack < swin->oldest_unacked_seq) {
        // Discard ACK, since we don't care.
        return;
    }

    int update_RTO = 1;
    if (ack == swin->oldest_unacked_seq) {
        ++swin->num_acks;
        // Check if this ACK ever timed out.
        if (swin->oas_timed_out) {
            // Do NOT update RTO values.
            update_RTO = 0;
        }
        if (swin->num_acks > 1) {
            update_RTO = 0;
        }

        if (swin->num_acks == 3) {
            // This is the 3rd ACK. Perform a fast re-transmit.
        }
    }

    assert(ack < swin->oldest_unacked_seq + treap_size(&swin->swin));

    if (ack > swin->oldest_unacked_seq) {
        int seq = swin->oldest_unacked_seq;
        for (; !treap_empty(&swin->swin) && seq < ack; ++seq) {
            treap_delete(&swin->swin, seq);
        }
        swin->oldest_unacked_seq = ack;
        swin->num_acks           = 0;
        swin->oas_timed_out      = 0;
    }

    if (update_RTO) {
        // rtt_update(&swin->rtt, BLAH);
    }

    // TODO: Invoke callback and send the packet on the network.

}

void swindow_timed_out() {
}

void swindow_set_window_size() {
}

void swindow_set_callback(swindow *swin, read_more_cb read_some, void *opaque) {
    swin->read_some = read_some;
    swin->opaque = opaque;
}

