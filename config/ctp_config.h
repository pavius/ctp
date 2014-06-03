/* 
 * Configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_CONFIGURATION_H_
#define __CTP_CONFIGURATION_H_

#include "common/utils/common.h"
#include "config/ctp_config_user.h"
#include "config/ctp_config_tunnel.h"
#include "config/ctp_config_nodeb.h"
#include "common/loggers/rx/ctp_log_rx.h"

/* max number of users per configuration */
#define CTP_CONFIG_MAX_USERS (0xFFFF)

/* max interface name size */
#define CTP_CONFIG_IF_MAX_NAME_SZ (64)

/* max console width */
#define CTP_CONFIG_MAX_CONSOLE_WIDTH (180)

/* preset configrations */
enum ctp_config_mode
{
    CTP_CFG_MODE_DISABLED,
    CTP_CFG_MODE_RLC_IUB_SIMULATE,
    CTP_CFG_MODE_RLC_IUB,
    CTP_CFG_MODE_BRIDGE,
    CTP_CFG_MODE_BRIDGE_VIA_TUNNEL,
    CTP_CFG_MODE_SCC,
    CTP_CFG_MODE_SCC_SIMULATE,
};

/* a configuration chain */
struct ctp_config_chain
{
    handle_t        sdu_pool;
    
    /* pdu pools */
    struct pdu_pools
    {
        unsigned int    data_size; /* header + payload */
        unsigned int    count;     /* # of pdus */
        handle_t        pool;

    } pdu_pools[4];

    /* number of pdu pools */
    unsigned int pdu_pool_count;
};

/* the global configuration */
struct ctp_config
{
    enum ctp_config_mode                                    ds_mode;
    enum ctp_config_mode                                    us_mode;
    struct ctp_config_user                                  user_db[CTP_CONFIG_MAX_USERS];
    char                                                    server_if[CTP_CONFIG_IF_MAX_NAME_SZ];
    char                                                    client_if[CTP_CONFIG_IF_MAX_NAME_SZ];
    char                                                    server_tunnel_if[CTP_CONFIG_IF_MAX_NAME_SZ];
    char                                                    client_tunnel_if[CTP_CONFIG_IF_MAX_NAME_SZ];
    enum ctp_log_rx_scheme                                  rx_err_scheme;
    TAILQ_HEAD(ctp_config_nodeb_list, ctp_config_nodeb)     nodeb_list;
    char                                                    descriptor_string[10 * 1024][CTP_CONFIG_MAX_CONSOLE_WIDTH];
    unsigned int                                            descriptor_lines;
    char                                                    config_file[256];
    struct ctp_config_chain                                 chain;

    /* modules configuration */
    struct
    {
        /* scheduler config */
        struct scheduler_config
        {
            unsigned int                                        max_user_leftover;
            unsigned int                                        max_common_leftover;

        } scheduler;

    } modules;
};

/* configuration init */
rv_t ctp_config_init();

/* parse configuration file */
rv_t ctp_config_parse_file(const char *config_file);

/* execute configuration chain */
rv_t ctp_config_execute();

/* get configuration */
const struct ctp_config* ctp_config_get();

/* get user by id */
struct ctp_config_user* ctp_config_get_user_by_id(const user_id_t user_id);

/* get user by index (order of creation) */ 
struct ctp_config_user* ctp_config_get_active_user_by_index(const unsigned int user_index);

/* get active number of users */
unsigned int ctp_config_get_active_users_count();

/* get active number of tunnels */
unsigned int ctp_config_get_active_tunnels_count();

/* get active number of nodebs */
unsigned int ctp_config_get_active_nodeb_count();

/* add a nodeb to configuration */
void ctp_config_nodeb_add(struct ctp_config_nodeb *nodeb);

#endif /* __CTP_CONFIGURATION_H_ */
