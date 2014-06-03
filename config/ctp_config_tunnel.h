/* 
 * Tunnel configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_CONFIG_TUNNEL_H_
#define __CTP_CONFIG_TUNNEL_H_

#include <linux/ip.h>
#include "common/utils/common.h"
#include "common/utils/data_struct.h"

/* max number of bytes that can be written as L2 */
#define CTP_CONFIG_TUNNEL_L2_MAX_SZ (256)

/* forward declare */
struct ctp_config_user;

/* a tunnel */
struct ctp_config_tunnel
{
    unsigned int                                            id;
    unsigned int                                            user_count;
    unsigned char                                           l2_header[CTP_CONFIG_TUNNEL_L2_MAX_SZ];
    unsigned int                                            l2_header_length;
    char                                                    l2_desc_string[512]; /* for logging */
    struct iphdr                                            ip_header;
    unsigned int                                            dscp;
    TAILQ_HEAD(ctp_config_user_list, ctp_config_user)       user_list;
    TAILQ_ENTRY(ctp_config_tunnel)                          nodeb_entry;
    struct ctp_config_nodeb                                 *nodeb;
};

/* initialize the user fp header (TODO: move to .c) */
#define ctp_config_tunnel_init_ip_header(tunnel)                                \
    do                                                                          \
    {                                                                           \
        tunnel->ip_header.ihl       = 5;                                        \
        tunnel->ip_header.version   = 4;                                        \
        tunnel->ip_header.ttl       = 255;                                      \
        tunnel->ip_header.protocol  = 0x11;                                     \
    } while (0)                                                                 
                                                                                
/* init tunnel */                                                               
#define ctp_config_tunnel_init(tunnel)                                          \
do                                                                              \
{                                                                               \
    TAILQ_INIT(&tunnel->user_list);                                             \
    ctp_config_tunnel_init_ip_header(tunnel);                                   \
} while (0)

/* add a user */
#define ctp_config_tunnel_add_user(tunnel, user)                                \
    TAILQ_INSERT_TAIL(&tunnel->user_list, user, tunnel_entry)

#endif /* __CTP_CONFIG_TUNNEL_H_ */

