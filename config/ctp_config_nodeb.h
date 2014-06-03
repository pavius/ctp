/* 
 * NodeB configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: October 9th, 2011
 *
 */

#ifndef __CTP_CONFIG_NODEB_H_
#define __CTP_CONFIG_NODEB_H_

#include <linux/ip.h>
#include <pthread.h>
#include "common/utils/common.h"
#include "common/utils/data_struct.h"

/* forward declare */
struct ctp_config_tunnel;
struct ctp_config_user;

/* nodeb scheduling state */
enum ctp_config_nodeb_scheduling_state
{
    CTP_CONFIG_NODEB_SCHED_STATE_UNLOCKED = 0,
    CTP_CONFIG_NODEB_SCHED_STATE_LOCKED
};

/* active user queue list */
struct ctp_config_nodeb_user_qs
{
    SIMPLEQ_HEAD(ctp_config_nodeb_user_q_list, ctp_config_user)      userq_list;
    unsigned int count;
};

/* a nodeb */
struct ctp_config_nodeb
{
    unsigned int                                                ip_address;
    unsigned int                                                max_bandwidth_bps;              /* bits per second  */
    unsigned int                                                max_bandwidth_bp_tti;           /* bytes per TTI    */
    unsigned int                                                common_leftover_credits;        /* credits leftover from scheduling users */    
    TAILQ_HEAD(ctp_config_tunnel_list, ctp_config_tunnel)       tunnel_list;                    
    TAILQ_ENTRY(ctp_config_nodeb)                               config_entry;                   /* entry into config.nodeb list */
    struct ctp_config_nodeb_user_qs                             user_queues[2];                 /* holds two lists of user queues */
    struct ctp_config_nodeb_user_qs                             *current_tti_active_user_qs;    /* see ctp_config_nodeb_add_active_user_q */
    struct ctp_config_nodeb_user_qs                             *next_tti_active_user_qs;       /* see ctp_config_nodeb_add_active_user_q */
    pthread_spinlock_t                                          lock;                           
    enum ctp_config_nodeb_scheduling_state                      scheduling_state;
    struct timespec                                             last_schedule_time;
    unsigned long long                                          max_schedule_interval;
    unsigned long long                                          schedule_interval_histogram[5];
};

/* init nodeb */                                                               
void ctp_config_nodeb_init(struct ctp_config_nodeb *nodeb);

/* post init nodeb */                                                               
void ctp_config_nodeb_post_config_init(struct ctp_config_nodeb *nodeb);

/* add a tunnel */
void ctp_config_nodeb_add_tunnel(struct ctp_config_nodeb *nodeb, struct ctp_config_tunnel *tunnel);

/* lock nodeb for scheduling */
void ctp_config_nodeb_lock_for_scheduling(struct ctp_config_nodeb *nodeb,
                                          struct timespec *current_time);

/* unlock nodeb for scheduling */
void ctp_config_nodeb_unlock_for_scheduling(struct ctp_config_nodeb *nodeb);

/* add a user queue to the list of active users. if the scheduling is unlocked (meaning the scheduler
 * is not currently handling this nodeb, the user will be added to current_tti_active_user_qs. If it
 * is, it will be added to next_tti_active_user_qs.
 */
void ctp_config_nodeb_add_active_user_q(struct ctp_config_nodeb *nodeb, 
                                        struct ctp_config_user *user);

/* pop a user from a user queue */
struct ctp_config_user *ctp_config_nodeb_pop_active_user(struct ctp_config_nodeb *nodeb, 
                                                         struct ctp_config_nodeb_user_qs *source_q);

#endif /* __CTP_CONFIG_NODEB_H_ */

