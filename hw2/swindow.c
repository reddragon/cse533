#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "treap.h"
#include "utils.h"
#include "swindow.h"

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
uint32_t rtt_get_RTO(rtt_info_t *rtt) {
    uint32_t rto = rtt->_8rto / 8.0;
    rto = imin(3000.0, imax(rto, 1000.0));
    return rto;
}

void rtt_scale_RTO(rtt_info_t *rtt, int factor) {
    rtt->_8rto *= factor;
}

tx_packet_info* make_tx_packet(packet_t *pkt) {
    tx_packet_info *txp = MALLOC(tx_packet_info);
    // Set sent_at_ms
    txp->sent_at_ms = current_time_in_ms();
    memcpy(&txp->pkt, pkt, sizeof(*pkt));
    return txp;
}

void swindow_dump(swindow *swin) {
    fprintf(stderr, "Sending Window { ACK: %d, NACKS: %d, NEXTSEQ: %d, RWIN: %d, RBUFF:%d, NTIMEOUTS: %d, TREAPSZ: %d, isEOF: %s }\n",
            swin->oldest_unacked_seq,
            swin->num_acks,
            swin->next_seq,
            swin->rwinsz,
            swin->rbuffsz,
            swin->oas_num_time_outs,
            treap_size(&swin->swin),
            swin->isEOF ? "TRUE" : "FALSE");
}

void swindow_init(swindow *swin, int fd, int fd2, struct sockaddr *csa,
                  int sbuffsz, read_more_cb read_some,
                  void *opaque, ack_cb advanced_ack_cb, end_cb on_end) {
    treap_init(&swin->swin);
    swin->oldest_unacked_seq = -1;
    swin->fd                 = fd;
    swin->fd2                = fd2;
    swin->csa                = csa;
    swin->num_acks           = 1;
    swin->next_seq           = 0;
    swin->rwinsz             = 0;
    swin->rbuffsz            = 0;
    swin->sbuffsz            = sbuffsz;
    swin->oas_num_time_outs  = 0;
    swin->read_some          = read_some;
    swin->opaque             = opaque;
    swin->advanced_ack_cb    = advanced_ack_cb;
    swin->on_end             = on_end;
    rtt_info_init(&swin->rtt);
}

void swindow_received_ACK(swindow *swin, int ack, int rwinsz) {
    fprintf(stderr, "swindow_received_ACK(ACK: %d, RWINSZ: %d)\n[ENTER] ", ack, rwinsz);
    swindow_dump(swin);
    swindow_received_ACK_real(swin, ack, rwinsz);
    fprintf(stderr, "[LEAVE] ");
    swindow_dump(swin);
}

// This function also updates the receiving buffer and receiving
// window size.
void swindow_received_ACK_real(swindow *swin, int ack, int rwinsz) {
    // 'ack' the the sequence number of the next *expected* sequence
    // number.
    if (ack < swin->oldest_unacked_seq) {
        // Discard ACK, since we don't care.
        fprintf(stderr, "Dsiscaring ACK: %d since it is < oldest unacked SEQ: %d\n", ack, swin->oldest_unacked_seq);
        return;
    }

    if (ack == 1) {
        // Set rbuffsz since this is the 1st packet.
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
        swin->num_acks           = 1;
        swin->oas_num_time_outs  = 0;
    }

    swin->rwinsz = rwinsz;

    // The effective window size
    if (rwinsz == 0) {
        rwinsz = 1;
    }
    const int last_seq_no_we_can_send = ack + rwinsz - 1;

    assert_le(treap_size(&swin->swin), swin->sbuffsz);

    // Invoke callback and send the packet on the network.
    while ((swin->isEOF == FALSE) &&
           (swin->next_seq <= last_seq_no_we_can_send) &&
           (treap_size(&swin->swin) < swin->sbuffsz)) {
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
}

// We assume that the packet with SEQ # (seq) is available in swin->swin.
void swindow_transmit_packet(swindow *swin, int seq) {
    fprintf(stderr, "swindow_transmit_packet(SEQ: %d)\n", seq);
    swindow_dump(swin);

    int r = -1;
    tx_packet_info *txp = (tx_packet_info*)treap_get_value(&swin->swin, seq);
    assert(txp);
    // TODO: Set the SO_DONTROUTE flag on the socket to start off with if we need to use it.
    errno = EINTR;
    while (r < 0 && errno == EINTR) {
        r = send(swin->fd, &txp->pkt, sizeof(txp->pkt), 0);
    }
    if (r < 0) {
        fprintf(stderr, "Error sending data on line %d::", __LINE__);
        perror("send");
        if (seq > 1) {
            exit(1);
        }
    }

    if (swin->fd2 != -1) {
        // Send the new port number on the existing socket.
        r = -1;
        errno = EINTR;
        while (r < 0 && errno == EINTR) {
            r = sendto(swin->fd2, &txp->pkt, sizeof(txp->pkt), 0, swin->csa, sizeof(SA));
        }
        if (r < 0) {
            fprintf(stderr, "Error sending data on line %d::", __LINE__);
            perror("sendto");
        }
    }
}

void swindow_timed_out(swindow *swin) {
    fprintf(stderr, "swindow_timed_out()\n");
    swindow_dump(swin);

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
