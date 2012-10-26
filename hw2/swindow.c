#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "treap.h"

//                          opaque, buffer, size
typedef int  (*read_more_cb)(void*,  void*,  int);

enum { TX_SUCCESS=0, TX_FAILURE=1 };
//                     status (0->success; 1->failure)
typedef void (*end_cb)(int);

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


// Periodically update the RTO values. mRTT is in 'ms'.
void rtt_update(rtt_info *rtt, int mRTT) {
    int _8mRTT = mRTT * 8;
    int _8delta = _8mRTT - rtt->_8srtt;
    rtt->_8srtt += (_8delta / 8);
    rtt->_8rttvar = (3 * (rtt->_8rttvar) + _8delta) / 4;
    rtt->_8rto = rtt->_8srtt + (4 * rtt->_8rttvar);
}

// Fetch the RTO in 'ms'.
double rtt_get_RTO(rtt_info *rtt) {
    double rto = (double)rtt->_8rto / 8.0;
    rto = fmin(3.0, fmax(rto, 1.0));
    return rto;
}

// Struct for packet sent.
typedef struct tx_packet_info {
    uint32_t sent_at_ms;
    packet_t pkt;
} tx_packet_info;

tx_packet_info* make_tx_packet(packet_t *pkt) {
    tx_packet_info *txp = MALLOC(tx_packet_info);
    // Set sent_at_ms
    txp->sent_at_ms = current_time_in_ms();
    memcpy(txp->pkt, pkt, sizeof(*pkt));
    return txp;
}

// The sending window.
typedef struct swindow {
    treap swin;             // A dictionary holding the in-flight packets
    int fd;                 // The FD of the connected client
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
    void *opaque;           // Opaque data passed to the read_some callback
    rtt_info rtt;
    BOOL EOF;               // EOF if TRUE
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

void swindow_init(swindow *swin, int fd, int swinsz, read_more_cb read_some, void *opaque, failed_cb on_timedout) {
    treap_init(&swin->swin);
    swin->oldest_unacked_seq = 1;
    swin->fd                 = fd;
    swin->num_acks           = 0;
    swin->next_seq           = 1;
    swin->swinsz             = swinsz;
    swin->rwinsz             = 0;
    swin->rbuffsz            = 0;
    swin->sbuffsz            = 0;
    swin->oas_timed_out      = 0;
    swin->read_some          = read_some;
    swin->opaque             = opaque;
    swin->on_end             = on_end;
    rtt_info_init(&swin->rtt);
}

// This function also updates the receiving buffer and receiving
// window size.
void swindow_received_ACK(swindow *swin, int ack, int rwinsz) {
    // 'ack' the the sequence number of the next *expected* sequence
    // number.

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
            // This is the 3rd ACK. Perform a fast re-transmit for
            // packet with seq # 'oldest_unacked_seq'. (TODO)
        }
    }

    assert(ack < swin->oldest_unacked_seq + treap_size(&swin->swin));
    uint32_t curr_time_ms = current_time_in_ms();

    if (ack > swin->oldest_unacked_seq) {
        int seq = swin->oldest_unacked_seq;
        int did_update_RTO = 0;

        for (; !treap_empty(&swin->swin) && seq < ack; ++seq) {
            tx_packet_info *txp = (tx_packet_info*)treap_get_value(&swin->swin, seq);
            if (txp) {
                if (update_RTO && !did_update_RTO) {
                    assert(curr_time_ms - txp->sent_at_ms);
                    rtt_update(&swin->rtt, curr_time_ms - txp->sent_at_ms);
                    did_update_RTO = 1;
                }
                free(txp);
            }
            treap_delete(&swin->swin, seq);
        }
        swin->oldest_unacked_seq = ack;
        swin->num_acks           = 0;
        swin->oas_timed_out      = 0;
    }

    swin->rwinsz = rwinsz;

    // The effective window size
    swin->swinsz = rwinsz - treap_size(&swin->swin) /* # of in-flight packets */;

    // TODO: Invoke callback and send the packet on the network.
    while ((swin->EOF == FALSE) && (swin->swinsz > 0)) {
        --swin->swinsz;
        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        int r = swin->read_some(swin->opaque, pkt.data, sizeof(pkt.data));
        if (r < 0) {
            // ERROR.
            assert(false);
        }
        if (r == 0) {
            // EOF.
            pkt.flags = FLAG_FIN;
            swin->EOF = TRUE;
        }
        // TODO. Set the seq #
        pkt.datalen = r;
        pkt.seq     = swin->next_seq++;

        tx_packet_info* txp = make_tx_packet(&pkt);

        // Add this packet to the treap and send it off.
        treap_insert(&swin->swin, pkt.seq, txp);
        swindow_transmit_packet(swin, pkt.seq);
    }

    if (swin->EOF && treap_empty(&swin->swin)) {
        // We are done!!
        swin->on_end(TX_SUCCESS);
        return;
    }

    // Set the rbuffsz when we get the first ACK. This happens in the
    // 3-way handshake function.
}

// We assume that the packet with SEQ # (seq) is available in swin->swin.
void swindow_transmit_packet(swindow *swin, int seq) {
    tx_packet_info *txp = (tx_packet_info*)treap_get_value(&swin->swin, seq);
    assert(txp);
    // TODO: Set the SO_DONTROUTE flag on the socket to start off with if we need to use it.
    Send(swin->fd, &txp->pkt, sizeof(txp->pkt), 0);
}

void swindow_timed_out(swindow *swin) {
    // Sending the packet with the seq # 'oldest_unacked_seq' timed out.
    ++swin->oas_num_time_outs;

    if (swin->oas_num_time_outs > 12) {
        // Bail out.
        swin->on_end(TX_FAILURE);
        return;
    }

    // Double the RTO value.
    swin->rtt._8rto *= 2;

    // Re-transmit the packet with seq # == oldest_unacked_seq.
    swindow_transmit_packet(swin, swin->oldest_unacked_seq);
}
