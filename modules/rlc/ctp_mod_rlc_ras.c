/* 
 * RLC reassembly module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdbool.h>
#include <string.h>
#include <linux/types.h>
#include "config/ctp_config_user.h"
#include "common/utils/assert.h"
#include "modules/rlc/ctp_mod_rlc_ras_prv.h"
#include "modules/base/ctp_module_msgpool.h"
#include "config/ctp_config.h"

/* parse an rlc header */
void ctp_mod_rlc_ras_parse_rlc_header(const struct ctp_mod_rlc_ras *rlc_ras,
                                      const struct ctp_config_user *user,
                                      const unsigned char *rlc_header_start,
                                      unsigned int *pdu_seqnum,
                                      bool *is_last_pdu_in_sdu,
                                      unsigned int *pdu_payload_size)
{
    /* according to user rlc mode */
    if (user->rlc_mode == CTP_CONFIG_RLC_MODE_UM)
    {
        unsigned char um_header;

        /* check if mac-d exists */
        if (user->rlc_macd_exists)
        {
            const unsigned char first_byte  = rlc_header_start[0],
        						second_byte = rlc_header_start[1];

            /* get UM header */
            um_header = (first_byte << 4) | (second_byte >> 4);
        }
        else
        {
            /* read um header as is */
            um_header = rlc_header_start[0];
        }

        /* set sequence number and is last */
        *pdu_seqnum             = (um_header >> 1);
        *is_last_pdu_in_sdu     = (um_header & 0x1);
    }
    else
    {
        unsigned short am_header;

        /* check if mac-d exists */
        if (user->rlc_macd_exists)
        {
            const unsigned short first_byte  = rlc_header_start[0],
                                 second_byte = rlc_header_start[1],
                                 third_byte  = rlc_header_start[2];

            /* get AM header - turn 0ABCD0 into ABCD */
            am_header = (first_byte << 12);
            am_header |= (second_byte << 4);
            am_header |= (third_byte >> 4);
        }
        else
        {
            /* as is */
            am_header = ((rlc_header_start[0] << 8) | rlc_header_start[1]);
        }

        /* parse */
        *pdu_seqnum             = (am_header >> 3) & 0xFFF; /* ignore D/C bit */
        *is_last_pdu_in_sdu     = (am_header & 0x1);
    }

    /* set PDU payload to max size. in the olden days this was taken from the MAC-d header */
    *pdu_payload_size = user->frag_payload_size;
}

/* peek at the ip header length and strip off any junk at the end of the packet */
void ctp_mod_rlc_ras_strip_padding_from_ipv4(const struct ctp_mod_rlc_ras *rlc_ras,
                                             struct ctp_module_message *ipv4_packet)
{
    unsigned short encoded_length, actual_length;
    int padding_bytes;

    /* point @ ipv4 header */
    struct iphdr *ip_header = (struct iphdr *)ctp_module_msg_get_head(ipv4_packet);

    /* check that this is indeed an ipv4 packet */
    ctp_assert(ip_header->version == 0x4 && ip_header->ihl == 0x5, 
               "RLC reassembly reassembled an invalid IP header");

    /* get the length as encoded by the header */
    memcpy(&encoded_length, &ip_header->tot_len, sizeof(encoded_length));

    /* to host */
    encoded_length = ntohs(encoded_length);

    /* get actual length of packet */
    actual_length = ctp_module_msg_get_bytes_written(ipv4_packet);

    /* now for some sanity */
    ctp_assert(encoded_length <= actual_length, 
               "IP header length must be smaller or equal to actual size in packet");

    /* get number of bytes */
    padding_bytes = (actual_length - encoded_length);

    /* anything to strip? */
    if (padding_bytes)
    {
        /* strip the bytes out of the tail*/
        ctp_module_msg_seek_tail(ipv4_packet, -padding_bytes);
    }
}

/* process a message */
void ctp_mod_rlc_ras_process_message(struct ctp_module *module, 
                                     struct ctp_module_message *message)
{
    unsigned char *input_pdus_current_pos;
    unsigned char *input_pdus_end_pos;
    unsigned int user_pdu_size;
    struct ctp_config_user *user;
    struct ctp_module_message *output_sdu;
    struct ctp_module_message *input_pdus;
    unsigned int received_seqnum;
    bool is_last_pdu_in_sdu, valid_pdu_received;
    unsigned int pdu_payload_size;

    /* get the rlc segmentator */
    struct ctp_mod_rlc_ras *rlc_ras = (struct ctp_mod_rlc_ras *)module;

    /* point to stats */
    struct ctp_mod_rlc_ras_stats *stats = (struct ctp_mod_rlc_ras_stats *)rlc_ras->module.stats;

    /* set input pdus for clarity */
    input_pdus = message;

    /* start at head, and get the end marker */
    input_pdus_current_pos  = ctp_module_msg_get_head(input_pdus);
    input_pdus_end_pos      = ctp_module_msg_get_tail(input_pdus);

    /* get message user */
    user = input_pdus->header.user;

    /* get the user's pdu size */
    user_pdu_size = (user->frag_payload_size + user->rlc_header_size);

    /* retreive the last sdu we're working on for the user */
    output_sdu = user->output_sdu;

    /* read all data in input pdus, assuming the first byte is the first byte of a pdu */
    while (input_pdus_current_pos < input_pdus_end_pos)
    {
        /* if we dont have an output sdu left over from a previous
         * input pdu we're worked on, allocate it
         */
        if (output_sdu == NULL && !user->discard_until_next_sdu)
        {
            /* allocate an sdu */
            output_sdu = ctp_module_msgpool_alloc_msg(rlc_ras->sdu_pool);

            /* must exist */
            ctp_assert(output_sdu != NULL, "Output SDUs depleted");

            /* set the user */
            output_sdu->header.user = input_pdus->header.user;

            /* initialize the message - an ethernet header will be prepended, seeing how
             * it is not sent on the wire
             */
            ctp_module_msg_reset_write_state(output_sdu, sizeof(struct ethhdr));
        }

        /* check that we have enough data for a pdu */
        if ((input_pdus_end_pos - input_pdus_current_pos) >= user_pdu_size)
        {
            /* read the current pdu header */
            ctp_mod_rlc_ras_parse_rlc_header(rlc_ras,
                                             user,
                                             input_pdus_current_pos,
                                             &received_seqnum,
                                             &is_last_pdu_in_sdu,
                                             &pdu_payload_size);

            /* */
            /* printf("<- %d\n", received_seqnum); */

            /* stats */
            stats[user->index].rx_pdus++;

            /* skip the header we just read */
            input_pdus_current_pos += user->rlc_header_size;

            /* set flag, indicating pdu is valid */
            valid_pdu_received = true;
        }
        else
        {
            /* stats */
            stats[user->index].not_enough_data_pdu++;

            /* handle error */
            ctp_log_rx_event(input_pdus, "Not enough data for RLC PDU (%d)", 
                             (input_pdus_end_pos - input_pdus_current_pos));

            /* invalid pdu */
            valid_pdu_received = false;

            /* assume not eof */
            is_last_pdu_in_sdu = false;
        }

        /* if we read enough data, look for other errors in the pdu */
        if (valid_pdu_received)
        {
            /* does the PDU have the expected seqnum? */
            if (received_seqnum != user->next_pdu_rx_seqnum)
            {
                /* stats */
                stats[user->index].oos_pdus++;

                /* set is so we expect the sequence after the OOS pdu we just got */
                user->next_pdu_rx_seqnum = received_seqnum;

                /* invalid pdu */
                valid_pdu_received = false;
            }
            /* is the pdu payload size indicating it is too big? */
            else if (pdu_payload_size > user->frag_payload_size)
            {
                /* stats */
                stats[user->index].invalid_pdu_size++;

                /* handle error */
                ctp_log_rx_event(input_pdus, "Invalid PDU payload size (%d) @ offset %d",
                                 pdu_payload_size, input_pdus_current_pos - input_pdus->data);

                /* invalid pdu */
                valid_pdu_received = false;
            }
        }

        /* if all is well */
        if (valid_pdu_received)
        {
        	/* are we discarding? */
        	if (!user->discard_until_next_sdu)
        	{
				/* copy the payload into the output sdu */
				ctp_module_msg_write_tail_buffer(output_sdu,
												 input_pdus_current_pos,
												 pdu_payload_size);
        	}
        }
        else
        {
            /* free the SDU we're working on  */
            if (output_sdu) ctp_module_msgpool_free_msg(output_sdu);

            /* indicate we're not working on an sdu */
            output_sdu = NULL;

            /* flag so that we will discard until we receive a PDU indicating end of SDU */
            user->discard_until_next_sdu = true;
        }

        /* expect next sequence number */
        ctp_config_user_inc_seqnum(user, user->next_pdu_rx_seqnum);

        /* skip over the payload and padding */
        input_pdus_current_pos += (user->frag_payload_size);

        /* if this is the last pdu for this sdu, send it outwards */
        if (is_last_pdu_in_sdu)
        {
            /* check if we're discarding the current SDU */
            if (!user->discard_until_next_sdu)
            {
                /* strip padding from the sdu, assuming it's an ipv4 packet */
                ctp_mod_rlc_ras_strip_padding_from_ipv4(rlc_ras, output_sdu);

                /* prepend the ethernet header we need to generate for this SDU */
                ctp_module_msg_write_head_buffer(output_sdu, 
                                                 (const unsigned char *)&user->tx_eth_header, 
                                                 sizeof(user->tx_eth_header));

                /* forward the output sdu */
                ctp_module_forward_message(rlc_ras, output_sdu);

                /* indicate we need to work on a new sdu */
                output_sdu = NULL;
            }
            else
            {
                /* we can now start receiving an SDU */
                user->discard_until_next_sdu = false;
            }
        }
    }

    /* save the current output sdu we're working on in the user configuration */
    user->output_sdu = output_sdu;

    /* free the input pdus */
    ctp_module_msgpool_free_msg(input_pdus);
}

/* create an rlc ras entity */
rv_t ctp_mod_rlc_ras_create(handle_t sdu_pool, handle_t *module)
{
    rv_t result;
    struct ctp_mod_rlc_ras *rlc_ras;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_rlc_ras), 
                               CTP_MODTYPE_RLC_RAS, "rlc ras", module);

    /* call base */
    if (result == RV_OK)
    {
        /* set ras stuff */
        rlc_ras = (struct ctp_mod_rlc_ras *)(*module);
            ctp_module_set_process_message(rlc_ras, ctp_mod_rlc_ras_process_message);
            rlc_ras->sdu_pool = sdu_pool;

        /* allocate the stats */
        ctp_module_allocate_per_user_stats(&rlc_ras->module, struct ctp_mod_rlc_ras_stats);
    }

    /* return the result */
    return result;
}

