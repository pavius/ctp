/* 
 * Ethernet receiver module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <unistd.h>
#include <linux/types.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include "common/utils/assert.h"
#include "modules/eth/ctp_mod_eth_rx_prv.h"
#include "modules/base/ctp_module_msgpool.h"

/* receiver thread function */
void ctp_mod_eth_rx_poll(struct ctp_module *module)
{
    /* counters */
    struct pfring_pkthdr packet_info;
    int recv_result;

    /* get the receiver from module */
    struct ctp_mod_eth_rx *receiver = ((struct ctp_mod_eth_rx *)module);
    
    /* allocate a buffer if we don't have a leftover sdu */
    if (receiver->sdu_message == NULL)
    {
        /* allocate an sdu */
        receiver->sdu_message = (struct ctp_module_message *)ctp_module_msgpool_alloc_msg(receiver->sdu_pool);

        /* if we tried to allocate, make sure we got it */
        ctp_assert(receiver->sdu_message != NULL, "Failed to allocate SDU");
    }

    /* initialize the message - there will be no need to append headers to it */
    ctp_module_msg_reset_write_state(receiver->sdu_message, 0);

    /* receive from the ring, don't wait for packet */
    recv_result = pfring_recv(receiver->eth.ring,
                              (char *)ctp_module_msg_get_tail(receiver->sdu_message),
                              CTP_MOD_ETH_RX_MAX_PAYLOAD_SZ,
                              &packet_info, 0);
    /* get a packet */
    if (recv_result > 0)
    {
        /* counters */
        receiver->stats.rx_frames++;
        receiver->stats.rx_bytes += packet_info.caplen;

        /* offset the tail by the bytes received */
        ctp_module_msg_seek_tail(receiver->sdu_message, packet_info.caplen);

        /* send the message to the output */
        ctp_module_forward_message(receiver, receiver->sdu_message);

        /* indicate the sdu was taken */
        receiver->sdu_message = NULL;
    }
    else if (recv_result < 0)
    {
        /* failed capture */
        printf("Error reading from ring\n");
    }
}

/* create an ethernet entity */
rv_t ctp_mod_eth_rx_create(handle_t sdu_pool, const char *name, 
                           const char *if_name, handle_t *module)
{
    rv_t result;
    struct ctp_mod_eth_rx *receiver;

    /* create base object */
    result = ctp_mod_eth_create(sizeof(struct ctp_mod_eth_rx), 
                                CTP_MODTYPE_ETH_RX,
                                name, if_name, true, module);

    /* call base */
    if (result == RV_OK)
    {
        /* set receiver stuff */
        receiver = (struct ctp_mod_eth_rx *)(*module);
            receiver->eth.module.poll = ctp_mod_eth_rx_poll;
            receiver->sdu_pool = sdu_pool;

        /* register statistics */    
        ctp_module_register_stats(&receiver->eth.module, 
                                  (unsigned char *)&receiver->stats, 
                                  sizeof(receiver->stats));

        /* create the ring and set promiscuous */    
        return ctp_mod_eth_ring_create(receiver) &&
               ctp_mod_eth_set_promisc(receiver, true);
    }
    else
    {
        /* error */
        return result;
    }
}

