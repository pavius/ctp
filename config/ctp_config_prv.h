/* 
 * Module message pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_CONFIGURATION_PRV_H_
#define __CTP_CONFIGURATION_PRV_H_

#include "config/ctp_config.h"

/* array of active users, indexed by creation order */
static struct ctp_config_user *ctp_config_active_users[CTP_CONFIG_MAX_USERS];

/* next index of user */
static unsigned int ctp_config_next_active_user_index = 0;

/* number of active users */
static unsigned int ctp_config_active_users_count = 0;

/* number of active tunnels */
static unsigned int ctp_config_active_tunnels_count = 0;

/* number of active nodebs */
static unsigned int ctp_config_active_nodeb_count = 0;

/* static configuration */
static struct ctp_config ctp_configuration;

/* error information */
struct ctp_config_error
{
    int             line;
    char            desc[256]; 
};

#endif /* __CTP_CONFIGURATION_PRV_H_ */
