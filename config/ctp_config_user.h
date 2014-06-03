/* 
 * User configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_CONFIG_USER_H_
#define __CTP_CONFIG_USER_H_

#include <stdbool.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include "common/utils/common.h"
#include "config/ctp_config_tunnel.h"
#include "common/buffer/ctp_buffer.h"

/* max number of supported classifiers */
#define CTP_CONFIG_USER_MAX_CLASSIFIERS (4)

/* an RLC mode */
enum ctp_config_rlc_mode
{
    CTP_CONFIG_RLC_MODE_UM = 0,
    CTP_CONFIG_RLC_MODE_AM
};

/* FP format */
enum ctp_config_fp_format
{
    CTP_CONFIG_FP_FORMAT_HS = 0,
    CTP_CONFIG_FP_FORMAT_DCH
};

/* user queue state */
enum ctp_config_user_q_state
{
    CTP_CONFIG_USER_Q_STATE_INACTIVE = 0,
    CTP_CONFIG_USER_Q_STATE_ACTIVE
};

/* a user id type */
typedef unsigned short user_id_t;

/* HS frame protocol header */
struct ctp_config_user_fp_hs_header
{
    unsigned short          pad1;                
    unsigned short          pdu_size_in_bits;
    unsigned char           pdu_count;
    unsigned short          pad2;

} __attribute__((packed));

/* DCH frame protocol header */
struct ctp_config_user_fp_dch_header
{
    unsigned char           control_data;
    unsigned char           pad1;
    unsigned char           pdu_count;

} __attribute__((packed));

/* a frame protocol header */
struct ctp_config_user_fp_header
{
    enum ctp_config_fp_format   format;

    /* the actual header */
    union
    {
        struct ctp_config_user_fp_hs_header hs;
        struct ctp_config_user_fp_dch_header dch;
    };

    unsigned char *header_data;
    unsigned int  header_size;
};

/* error injection types */
#define CTP_CONFIG_USER_ERR_ALL                     (0xFFFFFFFF)
#define CTP_CONFIG_USER_ERR_FP_BAD_RLC_COUNT        (1 << 0)
#define CTP_CONFIG_USER_ERR_FP_BAD_RLC_SIZE         (1 << 1)
#define CTP_CONFIG_USER_ERR_RLC_BAD_SEQNUM          (1 << 2)
#define CTP_CONFIG_USER_ERR_RLC_NOT_ENOUGH_BYTES    (1 << 3)
#define CTP_CONFIG_USER_ERR_RLC_TOO_MANY_BYTES      (1 << 4)

/* a pdu */
struct ctp_pdu
{
    struct ctp_buffer_header        bufpool_header;
    unsigned char                   data[0];
};

/* a user */
struct ctp_config_user
{
    user_id_t                               id;
    unsigned int                            index;
    unsigned int                            ip_addr;
    bool                                    active;
    struct ctp_config_user_fp_header        fp_header;
    struct udphdr                           udp_header;
    enum ctp_config_rlc_mode                rlc_mode;
    unsigned int                            rlc_header_size;
    bool                                    rlc_macd_exists;
    struct ctp_module                       *handlers[CTP_CONFIG_USER_MAX_CLASSIFIERS];
    unsigned int                            frag_payload_size;
    unsigned int                            next_pdu_tx_seqnum;
    unsigned int                            next_pdu_rx_seqnum;
    unsigned int                            pdu_seqnum_wrap;
    unsigned int                            next_frame_tx_seqnum;
    unsigned int                            next_frame_rx_seqnum;
    struct ctp_module_message               *output_sdu;
    struct ctp_module_message               *pending_output_pdus;
    struct ctp_config_tunnel                *tunnel;
    unsigned int                            total_required_tunnel_header;
    unsigned int                            total_required_tunnel_tail;
    bool                                    discard_until_next_sdu;
    struct ethhdr                           rx_eth_header;  /* as received in the input */
    struct ethhdr                           tx_eth_header;  /* as will be generated on output */
    TAILQ_ENTRY(ctp_config_user)            tunnel_entry;   /* entry into tunnel.user list */
    handle_t                                pdu_q;
    enum ctp_config_user_q_state            pdu_q_state;
    SIMPLEQ_ENTRY(ctp_config_user)          pdu_q_active_entry;     /* entry into nodeb.active_queue */
    unsigned int                            pdu_q_leftover_credits; /* used in scheduling            */

    /* control generator */
    struct
    {
        unsigned int rate;
        unsigned int min_size;
        unsigned int max_size;

    } gen_control;

    /* traffic generator */
    struct
    {
        unsigned int rate;
        unsigned int min_size;
        unsigned int max_size;

    } gen_traffic;

    /* error injection */
    struct
    {
        unsigned int rate;
        unsigned int err_mask;

    } err_injection;
};

/* increment a seqnum */
#define ctp_config_user_inc_seqnum(user, seqnum)        \
    if (++seqnum > user->pdu_seqnum_wrap) seqnum = 0;

/* calculate the total header to be prepended to this user towards the tunnel:
 * 12 bytes: src/dst MAC address 
 * l2 header length: includes the ethertype and any static L2 globbed on from configuration 
 * IP header 
 * UDP header 
 * FP header 
 */
#define ctp_config_user_calc_tunnel_header_sz(user)                                     \
    12 + user->tunnel->l2_header_length +                                               \
    sizeof(struct iphdr) + sizeof(struct udphdr) +                                      \
    user->fp_header.header_size

/* initialize a user */
void ctp_config_user_init(struct ctp_config_user *user);

/* set user from configuration */
void ctp_config_user_post_init(struct ctp_config_user *user);

/* fill in the user fields */
void ctp_config_user_fill_user_rlc_fields(struct ctp_config_user *user);

/* initialize the user fp header */
void ctp_config_user_init_fp_header(struct ctp_config_user *user);

/* set seqnum into frame protocol */
void ctp_config_user_encode_frame_seqnum(struct ctp_config_user_fp_header *fp_header, 
                                         const unsigned int frame_seqnum);

/* set seqnum into frame protocol */
void ctp_config_user_decode_frame_seqnum(struct ctp_config_user *user,
                                         const unsigned char *fp_header, 
                                         unsigned int *frame_seqnum);

/* increment a seqnuence number */
void ctp_config_user_increment_frame_seqnum(unsigned int *frame_seqnum);

/* get max sequence number */
#define ctp_config_user_max_frame_seqnum() (0x00FFFFFF)

/* get max number of pdus for a given user */
unsigned int ctp_config_user_max_pdus(struct ctp_config_user *user);

/* initialize an fp header */
void ctp_config_user_fp_header_fields_set(struct ctp_config_user *user,
                                          const unsigned char *fp_header, 
                                          const bool is_control,
                                          const unsigned char pdu_count);

/* initialize an fp header */
void ctp_config_user_fp_header_fields_get(struct ctp_config_user *user,
                                          const unsigned char *fp_header, 
                                          bool *is_control,
                                          unsigned char *pdu_count);

/* randomly determine if an error should be injected */
bool ctp_config_user_inject_error(const struct ctp_config_user *user);

/* 
 * User queue management
 */

/* lock the user queue */
void ctp_config_user_q_lock(struct ctp_config_user *user);

/* unlock the user queue */
void ctp_config_user_q_unlock(struct ctp_config_user *user);

/* push pdu onto the queue, assuming it was locked */
void ctp_config_user_q_push_pdu(struct ctp_config_user *user, 
                                struct ctp_pdu *pdu);

/* pull a number of pdus into a message */
void ctp_config_user_q_pull_pdus(struct ctp_config_user *user, 
                                 const unsigned int bytes_to_pull,
                                 handle_t message_pool,
                                 struct ctp_module_message *messages[],
                                 const unsigned int max_messages,
                                 unsigned int *message_count,
                                 unsigned int *bytes_in_q_before_pull,
                                 unsigned int *bytes_not_pulled,
                                 unsigned int *bytes_remaining_in_q);

#endif /* __CTP_CONFIG_USER_H_ */

