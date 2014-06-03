/* 
 * User configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: August 14, 2011
 *
 */

#include <string.h>
#include "config/ctp_config_user.h"
#include "modules/base/ctp_module.h"
#include "modules/base/ctp_module_msgpool.h"
#include "common/utils/assert.h"

/* set seqnum into frame protocol */
void ctp_config_user_encode_frame_seqnum(struct ctp_config_user_fp_header *fp_header, 
                                         const unsigned int frame_seqnum)
{
#if 0
	/* take only 24 bits */
	const unsigned int encoded_frame_seqnum = htonl(frame_seqnum & 0x00FFFFFF);

	/* to try and remain endian-safe, encode using pointers and not bitwise */
	const unsigned short *low_part = (const unsigned short *)&encoded_frame_seqnum,
						 *hi_part = low_part + 1;

    /* store 32 bits into the padding bytes */
    fp_header->pad1 = *low_part;
    fp_header->pad2 = *hi_part;
#endif
}
    
/* set seqnum into frame protocol */
void ctp_config_user_decode_frame_seqnum(struct ctp_config_user *user,
                                         const unsigned char *fp_header, 
                                         unsigned int *frame_seqnum)
{
#if 0
    /* read 32 bits from the padding bytes, as encoded by ctp_config_user_encode_frame_seqnum  */
	*frame_seqnum = (unsigned int)(fp_header->pad2 << 16);
    *frame_seqnum |= (unsigned int)(fp_header->pad1);

    /* to host */
    *frame_seqnum = ntohl(*frame_seqnum);
#endif
}

/* increment a seqnuence number */
void ctp_config_user_increment_frame_seqnum(unsigned int *frame_seqnum)
{
    unsigned int seqnum = *frame_seqnum;

    /* does it exceed 24 bits if incremented? */
    if (++seqnum > ctp_config_user_max_frame_seqnum())
    {
        /* to zero with you */
        seqnum = 0;
    }

    /* write back */
    *frame_seqnum = seqnum;
}

/* get max number of pdus for a given user */
unsigned int ctp_config_user_max_pdus(struct ctp_config_user *user)
{
    if (user->frag_payload_size == 40) return 31;
    else return 15;
}

/* 
 * User queue management
 */

/* lock the user queue */
void ctp_config_user_q_lock(struct ctp_config_user *user)
{
    /* delegate to user queue */
    ctp_bufq_lock(user->pdu_q);
}

/* unlock the user queue */
void ctp_config_user_q_unlock(struct ctp_config_user *user)
{
    /* delegate to user queue */
    ctp_bufq_unlock(user->pdu_q);
}

/* push pdu onto the queue, assuming it was locked */
void ctp_config_user_q_push_pdu(struct ctp_config_user *user, struct ctp_pdu *pdu)
{
    /* push pdu onto the per-user pdu queue */
    ctp_bufq_push_tail(user->pdu_q, pdu);

    /* are we inactive? */
    if (user->pdu_q_state == CTP_CONFIG_USER_Q_STATE_INACTIVE)
    {
        /* add ourselves to our node-b as an active queue */
        ctp_config_nodeb_add_active_user_q(user->tunnel->nodeb, user);

        /* switch to active state */
        user->pdu_q_state = CTP_CONFIG_USER_Q_STATE_ACTIVE;
    }
}

/* allocate and init a message for output */
struct ctp_module_message* ctp_config_user_q_allocate_output_message(handle_t message_pool,
                                                                     struct ctp_config_user *user)
{
    struct ctp_module_message *output_message;

    /* allocate a message to hold the encoded PDUs */
    output_message = ctp_module_msgpool_alloc_msg(message_pool);
    ctp_assert(output_message != NULL, "Depleted output messages");

    /* set the user */
    output_message->header.user = user;

    /* zero out the pdu count */
    output_message->header.pdu_count = 0;

    /* initialize the message - leave room for the header to be attached to this message
     * according to the user configuration
     */
    ctp_module_msg_reset_write_state(output_message, user->total_required_tunnel_header);

    /* return message */
    return output_message;
}

/* shove a message into the array and nullify it */
void ctp_config_user_q_save_message_in_array(struct ctp_module_message **message,
                                             struct ctp_module_message *messages[],
                                             const unsigned int max_messages,
                                             unsigned int *current_message_idx)
{
    /* not enough space in current message; shove to array and work on next message */
    ctp_assert(*current_message_idx < max_messages, "Not enough room for messages");
    messages[*current_message_idx] = *message;

    /* if there's another message, shove it to the next slot */
    (*current_message_idx)++;

    /* nullify the message so that we allocate another one */
    *message = NULL;
}

/* pull a number of pdus into an array of messages */
void ctp_config_user_q_pull_pdus(struct ctp_config_user *user, 
                                 const unsigned int bytes_to_pull,
                                 handle_t message_pool,
                                 struct ctp_module_message *messages[],
                                 const unsigned int max_messages,
                                 unsigned int *message_count,
                                 unsigned int *bytes_in_q_before_pull,
                                 unsigned int *bytes_not_pulled,
                                 unsigned int *bytes_remaining_in_q)
{
    struct ctp_pdu *pdu = (struct ctp_pdu *)!NULL;
    int bytes_left_to_pull = bytes_to_pull;
    unsigned int total_bytes_pulled = 0;
    unsigned int current_message_idx = 0;
    struct ctp_module_message *current_message = NULL;
    unsigned int payload_size_distortion = 0;

    /* calculate the number of valid bytes in a pdu */
    const unsigned int pdu_payload = user->frag_payload_size + user->rlc_header_size;

    /* set log counter */
    *bytes_in_q_before_pull = ctp_bufq_buffer_count(user->pdu_q) * pdu_payload;

    /* while we still have enough credits to send at least one pdu */
    while (bytes_left_to_pull >= pdu_payload)
    {
        /* pull pdu */
        pdu = (struct ctp_pdu *)ctp_bufq_pull_head(user->pdu_q);

        /* if pdu is NULL, there' nothing left to send */
        if (pdu == NULL) break;

        /* if we got a pdu, shove it to the message */
        while (pdu != NULL)
        {
            /* do we have a message to populate? */
            if (current_message == NULL)
            {
                /* allocate and initialize it */
                current_message = ctp_config_user_q_allocate_output_message(message_pool, user);
            }

            /* do we have enough space to shove into this message? */
            if (ctp_module_msg_tail_room_left(current_message) >= pdu_payload && 
                current_message->header.pdu_count < ctp_config_user_max_pdus(user))
            {
                /* set bad payload */
                if (user->err_injection.err_mask & CTP_CONFIG_USER_ERR_RLC_NOT_ENOUGH_BYTES && 
                    ctp_config_user_inject_error(user))
                {
                    /* remove 5 bytes from the payload */
                    payload_size_distortion = 5;
                }

                /* write to message */
                ctp_module_msg_write_tail_buffer(current_message, pdu->data, pdu_payload - payload_size_distortion);

                /* decrement bytes left */
                bytes_left_to_pull -= pdu_payload;

                /* for statistics */
                total_bytes_pulled += pdu_payload;

                /* add to number of pdus in message */
                current_message->header.pdu_count++;

                /* done with this PDU */
                ctp_bufpool_free_buf(pdu);
                pdu = NULL;
            }
            else
            {
                /* no more room for pdu in message; shove message into array */
                ctp_config_user_q_save_message_in_array(&current_message, 
                                                        messages, max_messages,
                                                        &current_message_idx);

                /* it's possible that PDU still has data, in this case leave it so it will
                 * be shoved into the next message
                 */
            }
        }
    } 

    /* if we were working on a message and we ran out of bytes or data in the queue */
    if (current_message != NULL)
    {
        /* not enough pdus to fill a message all the way, shove the partial message into the array */
        ctp_config_user_q_save_message_in_array(&current_message, 
                                                messages, max_messages,
                                                &current_message_idx);
    }

    /* update counters */
    *bytes_not_pulled = (bytes_to_pull - total_bytes_pulled);
    *bytes_remaining_in_q = ctp_bufq_buffer_count(user->pdu_q) * pdu_payload;

    /* set number of messages populated */
    *message_count = current_message_idx;
}

/* fill in the user fields */
void ctp_config_user_init_rlc_fields(struct ctp_config_user *user)
{
    /* set whether macd exists according to fp format */
    switch (user->fp_header.format)
    {
        case CTP_CONFIG_FP_FORMAT_HS:   user->rlc_macd_exists = true;  break;
        case CTP_CONFIG_FP_FORMAT_DCH:  user->rlc_macd_exists = false; break;
    }

    /* um */
    if (user->rlc_mode == CTP_CONFIG_RLC_MODE_UM)
    {
        user->rlc_header_size   = 1;
        user->pdu_seqnum_wrap   = 127;
    }
    else
    {
        /* set according to AM */
        user->rlc_header_size   = 2;
        user->pdu_seqnum_wrap	= 4095;
    }

    /* if macd exists, account for it */
    if (user->rlc_macd_exists) user->rlc_header_size++;
}

/* initialize the user fp header - must be called after ctp_config_user_init_rlc_fields */
void ctp_config_user_init_fp_fields(struct ctp_config_user *user)
{
    /* according to fp format */
    switch (user->fp_header.format)
    {
        /* HS */
        case CTP_CONFIG_FP_FORMAT_HS:

            /* just shove stuff into it */
            user->fp_header.hs.pad1 = 0;
            user->fp_header.hs.pdu_size_in_bits = (user->frag_payload_size + user->rlc_header_size - 1) * 8;
            user->fp_header.hs.pdu_size_in_bits <<= 3;
            user->fp_header.hs.pdu_size_in_bits = htons(user->fp_header.hs.pdu_size_in_bits);
            user->fp_header.hs.pdu_count = 0xFA;
            user->fp_header.hs.pad2 = 0;

            /* point to pdu and stuff */ 
            user->fp_header.header_data = (unsigned char *)&user->fp_header.hs;
            user->fp_header.header_size = sizeof(user->fp_header.hs);

            break;

        /* DCH */
        case CTP_CONFIG_FP_FORMAT_DCH:

            /* just shove stuff into it */
            user->fp_header.dch.control_data = 0;
            user->fp_header.dch.pad1 = 0;
            user->fp_header.dch.pdu_count = 0xFA;

            /* point to pdu and stuff */ 
            user->fp_header.header_data = (unsigned char *)&user->fp_header.dch;
            user->fp_header.header_size = sizeof(user->fp_header.dch);

            break;

        /* unknown */
        default:
            ctp_assert(false, "Invalid FP format");
            break;
    }
}

/* initialize a user */
void ctp_config_user_init(struct ctp_config_user *user)
{
    /* zero out all the fields */
    bzero(user, sizeof(struct ctp_config_user));

    /* set default values, to be overriden */
    user->fp_header.format = CTP_CONFIG_FP_FORMAT_HS;
}

/* set user from configuration */
void ctp_config_user_post_init(struct ctp_config_user *user)
{
    /* fill fields according to configuration */
    user->tunnel->user_count++;
    user->total_required_tunnel_tail = 2; /* 2 byte CRC at end of packet */
    user->tx_eth_header.h_proto = htons(0x0800); /* assume only IP */

    /* get user @ offset generated by generator */
    user->active                 = true;
    user->udp_header.check       = 0;
    user->discard_until_next_sdu = false;

    /* prepare everything in network order */
    user->udp_header.source = htons(user->udp_header.source);
    user->udp_header.dest = htons(user->udp_header.dest);

    /* fill in the user fields */
    ctp_config_user_init_rlc_fields(user);

    /* pre calculate user fp header (except for pdu count) */
    ctp_config_user_init_fp_fields(user);

    /* pre calculate l2 header size for user */
    user->total_required_tunnel_header = ctp_config_user_calc_tunnel_header_sz(user);

    /* initialize frame sequences and stuff */
    user->next_frame_tx_seqnum = 0;
    user->next_frame_rx_seqnum = 0;

    /* initialize pdu queue */
    ctp_bufq_create(&user->pdu_q);

    /* init state */
    user->pdu_q_state = CTP_CONFIG_USER_Q_STATE_INACTIVE;
    user->pdu_q_leftover_credits = 0;
}

/* initialize an fp header */
void ctp_config_user_fp_header_fields_set(struct ctp_config_user *user,
                                          const unsigned char *fp_header, 
                                          const bool is_control,
                                          const unsigned char pdu_count)
{
    unsigned char *pdu_count_ptr;

    /* according to type */
    if (user->fp_header.format == CTP_CONFIG_FP_FORMAT_HS)
    {
        /* point to header */
        struct ctp_config_user_fp_hs_header *hs = (struct ctp_config_user_fp_hs_header *)fp_header;

        /* set fields */
        hs->pad1 |= (is_control ? 0x1 : 0x0);
        pdu_count_ptr = &hs->pdu_count;

        /* set bad RLC size */
        if (user->err_injection.err_mask & CTP_CONFIG_USER_ERR_FP_BAD_RLC_SIZE && 
            ctp_config_user_inject_error(user))
        {
            /* set something random */
            hs->pdu_size_in_bits = (rand() % 0xFFFF);
        }
    }
    else
    {
        /* point to header */
        struct ctp_config_user_fp_dch_header *dch = (struct ctp_config_user_fp_dch_header *)fp_header;

        /* set fields */
        dch->control_data |= (is_control ? 0x1 : 0x0);
        pdu_count_ptr = &dch->pdu_count;
    }

    /* set pdu count */
    *pdu_count_ptr = pdu_count;

    /* set bad RLC error */
    if (user->err_injection.err_mask & CTP_CONFIG_USER_ERR_FP_BAD_RLC_COUNT && 
        ctp_config_user_inject_error(user))
    {
        /* set something random */
        *pdu_count_ptr = (rand() % 0xFF);
    }
}

/* initialize an fp header */
void ctp_config_user_fp_header_fields_get(struct ctp_config_user *user,
                                          const unsigned char *fp_header, 
                                          bool *is_control,
                                          unsigned char *pdu_count)
{
    /* according to type */
    if (user->fp_header.format == CTP_CONFIG_FP_FORMAT_HS)
    {
        /* point to header */
        struct ctp_config_user_fp_hs_header *hs = (struct ctp_config_user_fp_hs_header *)fp_header;

        /* set fields */
        *is_control = (hs->pad1 & 0x1);
        *pdu_count = hs->pdu_count;
    }
    else
    {
        /* point to header */
        struct ctp_config_user_fp_dch_header *dch = (struct ctp_config_user_fp_dch_header *)fp_header;

        /* set fields */
        *is_control = (dch->control_data & 0x1);
        *pdu_count = dch->pdu_count;
    }
}

/* randomly determine if an error should be injected */
bool ctp_config_user_inject_error(const struct ctp_config_user *user)
{
    /* just return against error rate */
    return (rand() % user->err_injection.rate) == 0;
}

