/* 
 * RLC segmentation
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdbool.h>
#include <string.h>
#include <linux/types.h>
#include "modules/rlc/ctp_mod_rlc_seg_prv.h"
#include "modules/base/ctp_module_msgpool.h"
#include "config/ctp_config_user.h"
#include "config/ctp_config.h"
#include "common/utils/assert.h"

/* write the rlc header */
void ctp_mod_rlc_seg_write_rlc_header(unsigned char *payload, 
                                      const struct ctp_config_user *user,
                                      unsigned int seqnum, 
                                      const bool last_pdu_for_sdu,
                                      unsigned int payload_size)
{
/* error injection for testing */
#if CTP_INJECT_ERROR_RATE

        /* inject an error, if needed */
        if (rand() % CTP_INJECT_ERROR_RATE == 0)
        {
            /* set payload size to something invalid */
            payload_size = 200;
        }

#endif 

    /* set bad RLC sequence number */
    if (user->err_injection.err_mask & CTP_CONFIG_USER_ERR_RLC_BAD_SEQNUM && 
        ctp_config_user_inject_error(user))
    {
        /* distort the sequence number */
        seqnum ^= 0x5A5A5A5A;
    }

    /* according to user mode */
    if (user->rlc_mode == CTP_CONFIG_RLC_MODE_UM)
    {
        /* set UM header */
        unsigned char um_header = ((seqnum << 1) & 0xFF);

        /* set E bit */
        um_header |= (last_pdu_for_sdu ? 0x1 : 0x0);

        /* check if mac-d exists */
        if (user->rlc_macd_exists)
        {
            /* UM header with MAC-d:
             * 4 bits: MAC-d - don't care
             * 7 bits: seqnum
             * 1 bit: E bit (last for SDU) 
             * 4 bits: MAC-d - don't care
             */

            /* set sequence number */
            unsigned short header = 0;

            /* shift payload size into MAC D header (4 bits on each side) */
            header = (um_header << 4);

            /* write the header */
            *payload++ = ((unsigned char)(header >> 8));
            *payload++ = ((unsigned char)header);
        }
        else
        {
            /* UM header without MAC-d:
             * 7 bits: seqnum
             * 1 bit: E bit (last for SDU) 
             */
            *payload++ = um_header;
        }
    }
    else
    {
        /* set AM header */
        unsigned short am_header = ((seqnum & 0xFFF) << 3);

        /* set d/c bit */
        am_header |= (1 << 15);

        /* set e bit */
        am_header |= (last_pdu_for_sdu ? 0x1 : 0x0);

        /* check if mac-d exists */
        if (user->rlc_macd_exists)
        {
            /* AM header with MAC-d:
             * 4 bits: MAC-d - don't care
             * 1 bit: Data/Control bit 
             * 12 bits: seqnum 
             * 2 bits: don't care 
             * 1 bit: E bit (last for SDU) 
             * 4 bits: MAC-d - don't care
             */

            /* get 12 bit sequence number */
            unsigned int header = 0;
        
            /* shift payload size into MAC D header (4 bits on each side) */
            header = (am_header << 4);

            /* write the header */
            *payload++ = ((unsigned char)(header >> 16));
            *payload++ = ((unsigned char)(header >> 8));
            *payload++ = ((unsigned char)header);
        }
        else
        {
            /* AM header without MAC-d:
             * 1 bit: Data/Control bit 
             * 12 bits: seqnum 
             * 2 bits: don't care 
             * 1 bit: E bit (last for SDU) 
             */

            /* write the header */
            *payload++ = ((unsigned char)(am_header >> 8));
            *payload++ = ((unsigned char)am_header);
        }
    }
}

/* register a PDU pool */
void ctp_mod_rlc_seg_register_pdu_pool(handle_t module, 
                                       handle_t pdu_pool, 
                                       const unsigned int pdu_size)
{
    unsigned int pool_idx;

    /* get seg */
    struct ctp_mod_rlc_seg *rlc_seg = (struct ctp_mod_rlc_seg *)module;

    /* iterate over pdu pool array */
    for (pool_idx = 0; pool_idx < array_size(rlc_seg->pdu_pools); ++pool_idx)
    {
        /* empty space? */
        if (rlc_seg->pdu_pools[pool_idx].pdu_size == 0)
        {
            /* save in this slot */
            rlc_seg->pdu_pools[pool_idx].pdu_size = pdu_size;
            rlc_seg->pdu_pools[pool_idx].pdu_pool = pdu_pool;

            /* done */
            return;
        }
    }

    /* no room */
    ctp_assert(0, "No more space for PDU pools");
}

/* get pdu pool by size of pdu */
handle_t ctp_mod_rlc_seg_get_pdu_pool_by_pdu_size(handle_t module, const unsigned int pdu_size)
{
    unsigned int pool_idx;

    /* get seg */
    struct ctp_mod_rlc_seg *rlc_seg = (struct ctp_mod_rlc_seg *)module;

    /* iterate over pdu pool array */
    for (pool_idx = 0; pool_idx < array_size(rlc_seg->pdu_pools); ++pool_idx)
    {
        /* will it fit? */
        if (rlc_seg->pdu_pools[pool_idx].pdu_size >= pdu_size)
            return rlc_seg->pdu_pools[pool_idx].pdu_pool;
    }

    /* no pdu */
    ctp_assert(0, "No PDU pool for PDU of size %d", pdu_size);
}

/* process a message */
void ctp_mod_rlc_seg_process_message(struct ctp_module *module, 
                                     struct ctp_module_message *message)
{
    unsigned int input_sdu_offset;
    unsigned int bytes_remain_in_input_sdu;
    struct ctp_config_user *user;
    struct ctp_module_message *output_pdus;
    unsigned int payload_bytes_to_write;
    bool last_pdu_for_sdu;
    unsigned int frag_payload_size;
    struct ctp_module_message *input_sdu;
    handle_t pdu_pool;

    /* get the rlc segmentator */
    struct ctp_mod_rlc_seg *rlc_seg = (struct ctp_mod_rlc_seg *)module;

    /* point to stats */
    struct ctp_mod_rlc_seg_stats *stats = (struct ctp_mod_rlc_seg_stats *)rlc_seg->module.stats;

    /* set input sdu, for clarity */
    input_sdu = message;

    /* get the user */
    user = input_sdu->header.user;

    /* currently this flow can only handle non-control framess */
    ctp_assert((input_sdu->header.flags & CTP_MODULE_MESSAGE_FLAG_CONTROL) == 0,
               "Can't shove control frames to user PDU queues");

    /* 
     * Strip away the ethernet header. The ethernet header will be used 
     * as the actual transport ethernet header sent outwards. To be able 
     * to do this, we need to save it in a local user storage 
     */ 

    /* save the ethernet header of the input sdu in user storage */
    memcpy(&user->rx_eth_header, ctp_module_msg_get_head(input_sdu), sizeof(user->rx_eth_header));

    /* skip the ethernet header */
    ctp_module_msg_seek_head(input_sdu, sizeof(user->rx_eth_header));

    /* 
     * Start segmentation of the input SDU
     */

    /* number of bytes left to send */
    bytes_remain_in_input_sdu = ctp_module_msg_get_bytes_written(input_sdu);

    /* as specified in configuration */
    frag_payload_size = (user->frag_payload_size);

    /* start at offset 0 into sdu */
    input_sdu_offset = 0;

    /* stats */
    stats[user->index].inputted_sdus++;
    stats[user->index].inputted_bytes += ctp_module_msg_get_bytes_written(input_sdu);

    /* get pdu pool */
    pdu_pool = ctp_mod_rlc_seg_get_pdu_pool_by_pdu_size(module, user->frag_payload_size);

    /* while there is data left to send */ 
    while (input_sdu_offset < ctp_module_msg_get_bytes_written(input_sdu))
    {
        unsigned char *pdu_payload;

        /* allocate pdu buffer */
        struct ctp_pdu *pdu = (struct ctp_pdu *)ctp_bufpool_alloc_buf(pdu_pool);
        ctp_assert(pdu != NULL, "PDU pool depleted");

        /* point to PDU paylaod */
        pdu_payload = pdu->data;

        /* get number of bytes to write */
        payload_bytes_to_write = get_minimum(bytes_remain_in_input_sdu, frag_payload_size);

        /* is this the last pdu for sdu? */
        last_pdu_for_sdu = (bytes_remain_in_input_sdu <= frag_payload_size);

        /* write the sequence number (AM/UM), setting the E bit */
        ctp_mod_rlc_seg_write_rlc_header(pdu_payload, 
                                         user, 
                                         user->next_pdu_tx_seqnum,
                                         last_pdu_for_sdu,
                                         payload_bytes_to_write);

        /* skip header */
        pdu_payload += user->rlc_header_size;

        /* increment user sequence number */
        ctp_config_user_inc_seqnum(user, user->next_pdu_tx_seqnum);

        /* write as much data as we can (must assume pdu was allocated with enough room */
        memcpy(pdu_payload, 
               ctp_module_msg_get_head(input_sdu) + input_sdu_offset, 
               payload_bytes_to_write);

        /* skip valid payload */
        pdu_payload += payload_bytes_to_write;

        /* check if we need to add padding */
        if (payload_bytes_to_write < frag_payload_size)
        {
            /* write padding */
            memcpy(pdu_payload, 
                   (unsigned char *)&rlc_seg->padding_sequence, 
                   frag_payload_size - payload_bytes_to_write);
        }

        /* increment offsets and such */
        bytes_remain_in_input_sdu -= payload_bytes_to_write;
        input_sdu_offset += payload_bytes_to_write;

        /* statistics */
        stats[user->index].tx_pdus++;

        /* lock the queue */
        ctp_config_user_q_lock(user);

        /* shove to user queue */
        ctp_config_user_q_push_pdu(user, pdu);


        /* unlock the queue */
        ctp_config_user_q_unlock(user);
    }

    /* free the input sdu */
    ctp_module_msgpool_free_msg(message);
}

/* create an ethernet entity */
rv_t ctp_mod_rlc_seg_create(handle_t *module)
{
    rv_t result;
    struct ctp_mod_rlc_seg *rlc_seg;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_rlc_seg), 
                               CTP_MODTYPE_RLC_SEG, "rlc seg", module);

    /* call base */
    if (result == RV_OK)
    {
        /* set xmitter stuff */
        rlc_seg = (struct ctp_mod_rlc_seg *)(*module);
            ctp_module_set_process_message(rlc_seg, ctp_mod_rlc_seg_process_message);

        /* init padding sequence */
        memset(rlc_seg->padding_sequence, 0x67, sizeof(rlc_seg->padding_sequence));

        /* init pdu pools */
        memset(rlc_seg->pdu_pools, 0x0, sizeof(rlc_seg->pdu_pools));

        /* allocate the stats */
        ctp_module_allocate_per_user_stats(&rlc_seg->module, struct ctp_mod_rlc_seg_stats);
    }

    /* return the result */
    return result;
}

