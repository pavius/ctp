/* 
 * Generator flow
 * Void (c) 2011 
 * 
 * Author: Eran Duchan
 * Written: November 11, 2011
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "modules/generator/ctp_mod_generator_flow_prv.h"
#include "modules/util/ctp_mod_util_analyzer.h"
#include "common/utils/assert.h"
#include "config/ctp_config_user.h"

/* create a flow */
rv_t ctp_mod_generator_flow_create(handle_t generator, const unsigned int pps, const unsigned int min_size, 
                                   const unsigned int max_size, struct ctp_config_user *user,
                                   struct ctp_mod_generator_flow **flow)
{
    /* allocate */
    struct ctp_mod_generator_flow *new_flow = malloc(sizeof(struct ctp_mod_generator_flow));
    ctp_assert(new_flow != NULL, "Failed to allocate flow");

    /* zero out the flow */
    bzero(new_flow, sizeof(struct ctp_mod_generator_flow));

    /* initialize it with static stuff */
    new_flow->generator     = (struct ctp_mod_generator *)generator;
    new_flow->min_size      = min_size;
    new_flow->max_size      = max_size;
    new_flow->next_tx_size  = min_size;
    new_flow->user          = user;

    /* calculate inter frame gap (in ns) from packets per second */
    ctp_assert(pps > 0 && pps <= 1000000000, "Invalid PPS value for flow");
    new_flow->ifg = 1000000000 / pps;

    /* register the flow */
    ctp_mod_generator_register_flow(generator, (handle_t)new_flow);

    /* set the flow */
    *flow = new_flow;

    /* success */
    return RV_OK;
}

/* populate dynamic fields */
rv_t ctp_mod_generator_flow_ipv4_udp_on_before_tx(struct ctp_mod_generator_flow *flow,
                                                  struct ctp_module_message *message)
{   
    struct iphdr *ip_header;
    struct ctp_mod_util_analyzer_header analyzer_tail;
    unsigned char *packet_head;
    unsigned int packet_length;

    /* point to ip header */
    ip_header = (struct iphdr *)(ctp_module_msg_get_head(message) + sizeof(struct ethhdr));

    /* message currently holds: eth/ip/udp/payload. The IP header size is
     * ip/udp/payload/tail
     */
    ip_header->tot_len = htons(ctp_module_msg_get_bytes_written(message) - 
                               sizeof(struct ethhdr) + 
                               sizeof(analyzer_tail));

    /* populate analyzer seqnum */
    analyzer_tail.seqnum = flow->seqnum;

    /* for debugging */
    packet_head = ctp_module_msg_get_head(message);
    packet_length = ctp_module_msg_get_bytes_written(message);

    /* and calculate CRC over everything */
    analyzer_tail.crc = crc32(0, NULL, 0);
    analyzer_tail.crc = crc32(analyzer_tail.crc, 
    						  packet_head,
    						  packet_length);

    /* to network */
    analyzer_tail.crc    = htonl(analyzer_tail.crc);
    analyzer_tail.seqnum = htonl(analyzer_tail.seqnum);

    /* now shove this at the end */
    ctp_module_msg_write_tail_buffer(message, (const unsigned char *)&analyzer_tail, sizeof(analyzer_tail));

    /* all ok */
    return RV_OK;
}

/* create a ip/udp flow */
void ctp_mod_generator_flow_create_ipv4_udp(handle_t generator,
                                            const char *eth_source, const char *eth_dest, 
                                            const unsigned int ip_source, const unsigned int ip_dest, 
                                            const unsigned short udp_source, const unsigned short udp_dest,
                                            const unsigned int pps, const unsigned int min_size, const unsigned int max_size)
{
    struct ctp_mod_generator_flow *flow;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct udphdr *udp_header;

    /* create the flow and initialize common stuff */
    ctp_mod_generator_flow_create(generator, pps, min_size, max_size, NULL, &flow);

    /* make sure we have enough space */
    /* ctp_assert(sizeof()) */

    /* point to headers */
    eth_header  = (struct ethhdr *)(flow->header);
    ip_header   = (struct iphdr *)(eth_header + 1);
    udp_header  = (struct udphdr *)(ip_header + 1);

    /* set ethernet header data */
    memcpy(eth_header->h_source, eth_source, sizeof(eth_header->h_source));
    memcpy(eth_header->h_dest, eth_dest, sizeof(eth_header->h_source));
    eth_header->h_proto = htons(ETH_P_IP);

    /* set ip headers */
    ip_header->saddr = htonl(ip_source);
    ip_header->daddr = htonl(ip_dest);
    ip_header->version = 0x4;
    ip_header->ihl = 0x5;
    ip_header->tot_len = htons(sizeof(struct iphdr) + 
                               sizeof(struct udphdr));

    /* set udp header */
    udp_header->source = udp_source;
    udp_header->dest = udp_dest;

    /* set header/trailer sizes */
    flow->header_size  = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    flow->trailer_size = sizeof(struct ctp_mod_util_analyzer_header);

    /* no additional headers are to be added to the message */
    flow->total_header_size = flow->header_size;

    /* set callbacks */
    flow->on_before_tx = ctp_mod_generator_flow_ipv4_udp_on_before_tx;
}

/* populate dynamic fields */
rv_t ctp_mod_generator_flow_control_on_before_tx(struct ctp_mod_generator_flow *flow,
                                                  struct ctp_module_message *message)
{
    /* mark as control */
    message->header.flags |= CTP_MODULE_MESSAGE_FLAG_CONTROL;

    /* do nothing */
    return RV_OK;
}

/* create raw generator */
void ctp_mod_generator_flow_create_control(handle_t generator, struct ctp_config_user *user,
                                           const unsigned int pps, const unsigned int min_size, const unsigned int max_size)
{
    struct ctp_mod_generator_flow *flow;

    /* create the flow and initialize common stuff */
    ctp_mod_generator_flow_create(generator, pps, min_size, max_size, user, &flow);

    /* set header/trailer sizes */
    flow->header_size       = 0; /* this flow adds no headers */
    flow->total_header_size = user->total_required_tunnel_header;
    flow->trailer_size      = 2; /* CRC trail */

    /* set callbacks */
    flow->on_before_tx = ctp_mod_generator_flow_control_on_before_tx;
}

