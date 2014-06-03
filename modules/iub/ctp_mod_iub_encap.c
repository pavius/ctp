/* 
 * Iub encapsulation module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include "modules/iub/ctp_mod_iub_encap_prv.h"
#include "config/ctp_config_user.h"
#include "config/ctp_config_tunnel.h"
#include "modules/base/ctp_module_msgpool.h"

/* process a message */
void ctp_mod_iub_encap_process_message(struct ctp_module *module, 
                                       struct ctp_module_message *message)
{
    unsigned short pdus_length;
    struct iphdr *ip_header;
    struct ctp_config_user *user;
    unsigned int frame_seqnum, udp_length_inc_header;

    /* get the user */
    user = message->header.user;

    /* lets check if this pdu contains enough pdus to be sent outwards */
    if (message->header.pdu_count >= 1)
    {
        /* get payload length */
        pdus_length = ctp_module_msg_get_bytes_written(message);
    
        /* 
         * Set frame protocol header from user
         */ 
        
/* check if we need to inject errors */    
#ifdef CTP_INJECT_ERROR_RATE
            
        /* inject an error, if needed */
        if (rand() % CTP_INJECT_ERROR_RATE == 0)
        {
            /* simulate reorder */
            user->next_frame_tx_seqnum -= 3;
        } 

#endif
                
        /* shove tx frame seqnum in frame protocol padding */
        ctp_config_user_encode_frame_seqnum(&user->fp_header, 
                                            user->next_frame_tx_seqnum);

        /* next time set next seqnum */
        ctp_config_user_increment_frame_seqnum(&user->next_frame_tx_seqnum);

        /* write FP header */
        ctp_module_msg_write_head_buffer(message, 
                                         (unsigned char *)user->fp_header.header_data,
                                         user->fp_header.header_size);
    
        /* update pdu count directly in message */
        ctp_config_user_fp_header_fields_set(user,
                                             ctp_module_msg_get_head(message),
                                             message->header.flags & CTP_MODULE_MESSAGE_FLAG_CONTROL,
                                             message->header.pdu_count);

        /* 
         * Set UDP header from user info 
         */ 

        /* calculate udp length including header */
        udp_length_inc_header = sizeof(struct udphdr) + /* UDP header */
                                user->fp_header.header_size + /* frame protocol */
                                pdus_length + /* RLC pdus */
                                2; /* CRC tail */
    
        /* start by updating udp header */
        user->udp_header.len = htons(udp_length_inc_header);
    
        /* write UDP header */
        ctp_module_msg_write_head_buffer(message, 
                                         (unsigned char *)&user->udp_header,
                                         sizeof(struct udphdr));
    
        /* 
         * Set IP header from tunnel info. 
         * Can't write to tunnel because it's shared by users 
         */
    
        /* write IP header */
        ctp_module_msg_write_head_buffer(message, 
                                         (unsigned char *)&user->tunnel->ip_header,
                                         sizeof(struct iphdr));
    
        /* get ip header */
        ip_header = (struct iphdr *)ctp_module_msg_get_head(message);
    
        /* NOTE TO SELF: check alignment here */
    
        /* set total length */
        ip_header->tot_len = htons(udp_length_inc_header + sizeof(struct iphdr));
    
        /* calculate ip checksum */
        ip_header->check = ip_chksum_calculate((unsigned short *)ip_header, sizeof(struct iphdr) / 2);
    
        /* 
         * Write L2 header from tunnel as is
         */
    
        /* write L2 header */
        ctp_module_msg_write_head_buffer(message, 
                                         (unsigned char *)&user->tunnel->l2_header,
                                         user->tunnel->l2_header_length);
    
        /* 
         * Write only the source MAC address from the input SDU
         */ 
    
        /* write source header */
        ctp_module_msg_write_head_buffer(message, 
                                         (const unsigned char *)&user->rx_eth_header.h_source,
                                         sizeof(user->rx_eth_header.h_source));

        /* write the 2 bytes user id */
        ctp_module_msg_write_head_byte(message, (user->id & 0xFF));
        ctp_module_msg_write_head_byte(message, (user->id >> 8));
    
        /* write magic number which is assumed to exist only in classified packets, unless followed
         * by 0xFFFF. This is used so that the classifier on the other side knows that this frame 
         * contains the user-id embedded in the MAC address and will prevent cases in which an 
         * unclassified frame just happens to have the same 2 bytes in the user-id location
         */
        ctp_module_msg_write_head_buffer(message,
                                         (const unsigned char *)&ctp_mod_iub_da_magic,
                                         sizeof(ctp_mod_iub_da_magic));

        /* 
         * Write 2 bytes constant at the end to simulate CRC
         */
        ctp_module_msg_write_tail_byte(message, 0xDE);
        ctp_module_msg_write_tail_byte(message, 0xAD);
    
/* check if we need to inject loss */    
#ifdef CTP_INJECT_LOSS_RATE
            
        /* inject an error, if needed */
        if (rand() % CTP_INJECT_LOSS_RATE == 0)
        {
            /* free the message */
            ctp_module_msgpool_free_msg(message);
        } 
        else

#endif

/* check if we need to log the frame */
#ifdef CTP_OUTPUT_IUB_TO_PCAP

        /* must write total frame length before logging */
        ctp_module_msg_save_written_data_state(message);

        /* log the event */
        ctp_log_rx_event(message, "Configured to output all Iub frames");

#endif

        /* send the message to the output */
        ctp_module_forward_message(module, message);

        /* indicate that this user has no pending pdus to be sent so that next time seg
         *  will allocate a message
         */
        user->pending_output_pdus = NULL;
    }
    else
    {
        /* not enough PDUs in the message - store in user. Segmentation will continue
         *  to fill this up or a timeout will expire and this will be sent outwards
         */
        user->pending_output_pdus = message;
    }
}

/* create an ethernet entity */
rv_t ctp_mod_iub_encap_create(handle_t *module)
{
    rv_t result;
    struct ctp_mod_iub_encap *iub_encap;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_iub_encap), 
                               CTP_MODTYPE_IUB_ENCAP, "iub encap", module);

    /* call base */
    if (result == RV_OK)
    {
        /* set iub_encap stuff */
        iub_encap = (struct ctp_mod_iub_encap *)(*module);
            ctp_module_set_process_message(iub_encap, ctp_mod_iub_encap_process_message);

        /* initialize magic numbers */
        ctp_mod_iub_da_magic = htonl(CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC);
    }

    /* return the result */
    return result;
}

