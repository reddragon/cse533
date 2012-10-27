#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "treap.h"
#include "utils.h"
#include "swindow.h"

#define fmax(X,Y) ((X)>(Y)?(X):(Y))
#define fmin(X,Y) ((X)<(Y)?(X):(Y))

void rtt_info_init(rtt_info_t *rtt) {
    rtt->_8srtt = 0;
    rtt->_8rttvar = 750 * 8;
    rtt->_8rto = rtt->_8srtt + rtt->_8rttvar * 4;
}

// Periodically update the RTO values. mRTT is in 'ms'.
void rtt_update(rtt_info_t *rtt, int mRTT) {
    int _8mRTT = mRTT * 8;
    int _8delta = _8mRTT - rtt->_8srtt;
    rtt->_8srtt += (_8delta / 8);
    rtt->_8rttvar = (3 * (rtt->_8rttvar) + _8delta) / 4;
    rtt->_8rto = rtt->_8srtt + (4 * rtt->_8rttvar);
}

// Fetch the RTO in 'ms'.
double rtt_get_RTO(rtt_info_t *rtt) {
    double rto = (double)rtt->_8rto / 8.0;
    rto = fmin(3.0, fmax(rto, 1.0));
    return rto;
}

tx_packet_info* make_tx_packet(packet_t *pkt) {
    tx_packet_info *txp = MALLOC(tx_packet_info);
    // Set sent_at_ms
    txp->sent_at_ms = current_time_in_ms();
    memcpy(&txp->pkt, pkt, sizeof(*pkt));
    return txp;
}

void swindow_init(swindow *swin, int fd, int fd2, struct sockaddr *csa,
                  int swinsz, read_more_cb read_some,
                  void *opaque, end_cb on_end) {
    treap_init(&swin->swin);
    swin->oldest_unacked_seq = -1;
    swin->fd                 = fd;
    swin->fd2                = fd2;
    swin->csa                = csa;
    swin->num_acks           = 0;
    swin->next_seq           = 0;
    swin->swinsz             = swinsz;
    swin->rwinsz             = 0;
    swin->rbuffsz            = 0;
    swin->sbuffsz            = 0;
    swin->oas_num_time_outs  = 0;
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
    fprintf(stderr, "swindow_received_ACK(ACK: %d, RWINSZ: %d)\n", ack, rwinsz);

    if (ack < swin->oldest_unacked_seq) {
        // Discard ACK, since we don't care.
        return;
    }

    if (ack == 1) {
        // Set rbuffsz.
        swin->rbuffsz = rwinsz;
    }

    BOOL update_RTO = TRUE;
    if (ack == swin->oldest_unacked_seq) {
        ++swin->num_acks;
        // Check if this ACK ever timed out.
        if (swin->oas_num_time_outs) {
            // Do NOT update RTO values.
            update_RTO = FALSE;
        }
        if (swin->num_acks > 1) {
            update_RTO = FALSE;
        }

        if (swin->num_acks == 4) {
            // This is the 4th ACK. Perform a fast re-transmit for
            // packet with seq # 'oldest_unacked_seq'.
            swindow_transmit_packet(swin, swin->oldest_unacked_seq);
        }
    }

    if (ack != swin->oldest_unacked_seq + 1) {
        update_RTO = FALSE;
    }

    if (ack > 0) {
        assert_lt(ack, swin->oldest_unacked_seq + treap_size(&swin->swin) + 1);
    }
    uint32_t curr_time_ms = current_time_in_ms();

    if (ack > swin->oldest_unacked_seq) {
        int seq = swin->oldest_unacked_seq;
        int did_update_RTO = 0;

        for (; !treap_empty(&swin->swin) && seq < ack; ++seq) {
            tx_packet_info *txp = (tx_packet_info*)treap_get_value(&swin->swin, seq);
            if (txp) {
                if (update_RTO && !did_update_RTO) {
                    assert_ge(curr_time_ms - txp->sent_at_ms, 0);
                    rtt_update(&swin->rtt, curr_time_ms - txp->sent_at_ms);
                    did_update_RTO = 1;
                }
                free(txp);
            }
            treap_delete(&swin->swin, seq);
        }
        swin->oldest_unacked_seq = ack;
        swin->num_acks           = 0;
        swin->oas_num_time_outs  = 0;
    }

    swin->rwinsz = rwinsz;

    // The effective window size
    swin->swinsz = rwinsz - treap_size(&swin->swin) /* # of in-flight packets */;

    // TODO: Invoke callback and send the packet on the network.
    while ((swin->isEOF == FALSE) && (swin->swinsz > 0)) {
        --swin->swinsz;
        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        int r = swin->read_some(swin->opaque, pkt.data, sizeof(pkt.data));
        if (r < 0) {
            // ERROR.
            swin->isEOF = TRUE;
            treap_clear(&swin->swin, free);
            swin->on_end(TX_FAILURE);
            return;
        }
        if (r == 0) {
            // EOF.
            pkt.flags = FLAG_FIN;
            swin->isEOF = TRUE;
        }
        // Set the seq #
        pkt.datalen = r;
        pkt.seq     = swin->next_seq++;

        if (pkt.seq == 0) {
            // This is the 1st packet.
            pkt.flags |= FLAG_SYN;
        }

        tx_packet_info* txp = make_tx_packet(&pkt);

        // Add this packet to the treap and send it off.
        treap_insert(&swin->swin, pkt.seq, txp);
        swindow_transmit_packet(swin, pkt.seq);
    }

    if (swin->isEOF && treap_empty(&swin->swin)) {
        // We are done!!
        swin->on_end(TX_SUCCESS);
        return;
    }

    // Set the rbuffsz when we get the first ACK. This happens in the
    // 3-way handshake function.
}

// We assume that the packet with SEQ # (seq) is available in swin->swin.
void swindow_transmit_packet(swindow *swin, int seq) {
    fprintf(stderr, "swindow_transmit_packet(SEQ: %d)\n", seq);
    tx_packet_info *txp = (tx_packet_info*)treap_get_value(&swin->swin, seq);
    assert(txp);
    // TODO: Set the SO_DONTROUTE flag on the socket to start off with if we need to use it.
    Send(swin->fd, &txp->pkt, sizeof(txp->pkt), 0);

    if (swin->fd2 != -1) {
        // Send the new port number on the existing socket.
        Sendto(swin->fd2, &txp->pkt, sizeof(txp->pkt), 0, swin->csa, sizeof(SA));
    }

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
