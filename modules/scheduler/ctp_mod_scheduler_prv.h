/* 
 * Ethernet scheduler module
 * Void (c) 2011
 *
 * Author: Eran Duchan
 * Written: October 11, 2011
 *
 */

#ifndef __CTP_MOD_SCHEDULER_PRV_H_
#define __CTP_MOD_SCHEDULER_PRV_H_

#include "modules/scheduler/ctp_mod_scheduler.h"
#include "modules/base/ctp_module.h"

/* type of log entry */
enum ctp_mod_scheduler_log_entry_type
{
    CTP_MOD_SCHEDULER_LOG_ET_SCHEDULE,
    CTP_MOD_SCHEDULER_LOG_ET_NODEB,
    CTP_MOD_SCHEDULER_LOG_ET_USER
};

/* log a schedule */
struct ctp_mod_scheduler_log_entry_schedule
{
    unsigned int            index;
};

/* log nodeb */
struct ctp_mod_scheduler_log_entry_nodeb
{
    struct timespec         time;
    unsigned int            active_user_cout;
    unsigned int            before_common_leftover;
    unsigned int            after_common_leftover;
    unsigned int            per_user_allocation;

};

/* log user */
struct ctp_mod_scheduler_log_entry_user
{
    unsigned int            idx;
    unsigned int            before_leftover;
    unsigned int            before_bytes_in_queue;
    unsigned int            total_given;
    unsigned int            unused;
    unsigned int            after_leftover;
    unsigned int            after_bytes_in_queue;
};

/* scheduler log entry */
struct ctp_mod_scheduler_log_entry
{
    enum ctp_mod_scheduler_log_entry_type type;

    /* log data */
    union
    {
        struct ctp_mod_scheduler_log_entry_schedule     schedule;
        struct ctp_mod_scheduler_log_entry_nodeb        nodeb;
        struct ctp_mod_scheduler_log_entry_user         user;

    } data;
};

/* scheduler module */
struct ctp_mod_scheduler
{
    struct ctp_module                      module;
    handle_t                               sdu_pool;
    struct ctp_mod_scheduler_stats         stats;
    handle_t                               schedule_log;
    unsigned int                           max_user_leftover;
    unsigned int                           max_common_leftover;
    handle_t                               log;
};

/* scheduling constants */

/* TODO: describe */
#define CTP_MOD_SCHEDULER_MAX_FRAMES_PER_TTI                  (2000)

#endif /* __CTP_MOD_SCHEDULER_PRV_H_ */
