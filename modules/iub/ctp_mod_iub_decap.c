/* 
 * Iub decapsulation module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <string.h>
#include <linux/types.h>
#include <stdlib.h>
#include "common/utils/assert.h"
#include "modules/iub/ctp_mod_iub_decap_prv.h"
#include "config/ctp_config_user.h"
#include "common/loggers/rx/ctp_log_rx.h"
#include "modules/base/ctp_module_msgpool.h"
#include "config/ctp_config.h"

/* get how many frames dropped according to the seqnum we got and what we were expecting */
void ctp_mod_iub_decap_calc_frames_dropped(const unsigned int received_frame_seqnum,  
                                           const unsigned int expected_frame_seqnum,
                                           unsigned long long *oos_frames,
                                           unsigned long long *possibly_reordered_frames)
{
    /* is the received seqnum larger than what we expected ? */
    if (received_frame_seqnum > expected_frame_seqnum)
    {
        /* the missing frames are the difference betwen what we expected and what we got */
         *oos_frames += received_frame_seqnum - expected_frame_seqnum;
    }
    /* we expcted a larger seqnum than what we got. could be wrap or could be OOS */
    else if (expected_frame_seqnum > received_frame_seqnum ) 
    {
        /* probably a wrap + lost packets */
        unsigned int difference = ((ctp_config_user_max_frame_seqnum() - expected_frame_seqnum) + 1 + received_frame_seqnum);

        /* if the difference is too big, this may be reordering */
        if (difference > 100000)
        {
            /* we may have received a frame out of order */
            *possibly_reordered_frames += 1;
        }
        else
        {
            /* diff is small, assume lost while wrapping */
            *oos_frames += difference;
        }
    }
    else /* should never get here, but still handle it */ 
        return;
}

/* process a message */
void ctp_mod_iub_decap_process_message(struct ctp_module *module, 
                                       struct ctp_module_message *message)
{
    const struct ethhdr *received_eth_header = (const struct ethhdr *)message->data;

    /* before we offset anything, save the current message state so that we can log it fully later */
    ctp_module_msg_save_written_data_state(message);

    /* minimal amount of data that the packet can hold is 12 bytes for ethernet,
     * tunnel header and tunnel tail
     */
    const unsigned int min_packet_size = message->header.user->total_required_tunnel_header +
                                         message->header.user->total_required_tunnel_tail;

    /* get module stats */
    struct ctp_mod_iub_decap_stats *stats = (struct ctp_mod_iub_decap_stats *)module->stats;

    /* check if there's enough data in the packet */
    if (ctp_module_msg_get_bytes_written(message) >= min_packet_size)
    {
        const unsigned char *fp_header;
        unsigned int received_frame_seqnum;
        bool is_control;
        unsigned char pdu_count;

        /* Once we get here, the source MAC is the source as was received @ the server side, the
         * dest is the special CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC 4 byte magic number + 2 byte user id 
         * and the ethertype is whatever the L2 says it is. We only need to take the source MAC from the 
         * frame, since the dest MAC is taken from configuration and ethertype is always 0x0800 
         */
        memcpy(&message->header.user->tx_eth_header.h_source, 
               received_eth_header->h_source,
               sizeof(message->header.user->tx_eth_header.h_source));

        /* HACK: use rx portion to fill in dest MAC. This won't work if rx/tx don't reside on same
         * machine
         */
        memcpy(&message->header.user->tx_eth_header.h_dest, 
               &message->header.user->rx_eth_header.h_dest,
               sizeof(message->header.user->tx_eth_header.h_dest));

        /* skip ether header + L2 so that we can get to the fp header */
        ctp_module_msg_seek_head(message, 
                                 message->header.user->total_required_tunnel_header - message->header.user->fp_header.header_size);

        /* point to header (assume no alignment contraints) */
        fp_header = message->header.write_head;

        /* get fields */
        ctp_config_user_fp_header_fields_get(message->header.user, 
                                             fp_header,
                                             &is_control,
                                             &pdu_count);

        /* check if control */
        if (!is_control)
        {
            /* get the sequence number */
            ctp_config_user_decode_frame_seqnum(message->header.user, fp_header, &received_frame_seqnum);

            /* is this frame the expected seqnum? */
            if (true /* received_frame_seqnum == message->header.user->next_frame_rx_seqnum */)
            {
                /* expect the next seqnum and wrap if this is god's will */
                ctp_config_user_increment_frame_seqnum(&message->header.user->next_frame_rx_seqnum);

                /* skip the fp header */
                ctp_module_msg_seek_head(message, message->header.user->fp_header.header_size);

                /* and remove the 2 byte crc at the end */
                ctp_module_msg_seek_tail(message, -message->header.user->total_required_tunnel_tail);

/* error injection for testing */
#ifdef CTP_INJECT_ERROR_RATE

                /* inject an error, if needed */
                if (rand() % CTP_INJECT_ERROR_RATE == 0)
                {
                    /* remove a few bytes off of the tail */
                    ctp_module_msg_seek_tail(message, -5);
                }

#endif 

                /* and forward. why can't all modules be this simple? */
                ctp_module_forward_message(module, message);
            }
            else /* handle frames received out of seqnuence (probably due to drop) */
            {
                /* get how many frames were dropped */
                ctp_mod_iub_decap_calc_frames_dropped(received_frame_seqnum,
                                                      message->header.user->next_frame_rx_seqnum,
                                                      &stats[message->header.user->index].oos_frames,
                                                      &stats[message->header.user->index].possibly_reordered_frames);

                /* sync with the received seqnum */
                message->header.user->next_frame_rx_seqnum = received_frame_seqnum;
                ctp_config_user_increment_frame_seqnum(&message->header.user->next_frame_rx_seqnum);

                /* free the message */
                ctp_module_msgpool_free_msg(message);
            }
        }
        else
        {
            /* free the message */
            ctp_module_msgpool_free_msg(message);
        }
    }
    else
    {
        /* stats */ 
        stats[message->header.user->index].not_enough_data_l2++;

        /* handle error */
        ctp_log_rx_event(message, "Not enough data for L2 transport (%d)", 
                         ctp_module_msg_get_bytes_written(message));

        /* free the message */
        ctp_module_msgpool_free_msg(message);
    }
}

/* create an ethernet entity */
rv_t ctp_mod_iub_decap_create(handle_t *module)
{
    rv_t result;
    struct ctp_mod_iub_decap *iub_decap;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_iub_decap), 
                               CTP_MODTYPE_IUB_DECAP, "iub decap", module);

    /* call base */
    if (result == RV_OK)
    {
        /* set iub_decap stuff */
        iub_decap = (struct ctp_mod_iub_decap *)(*module);
            ctp_module_set_process_message(iub_decap, ctp_mod_iub_decap_process_message);

        /* allocate the stats */
        ctp_module_allocate_per_user_stats(&iub_decap->module, struct ctp_mod_iub_decap_stats);
    }

    /* return the result */
    return result;
}

