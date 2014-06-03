/* 
 * Ethernet scheduler module
 * Void (c) 2011
 *
 * Author: Eran Duchan
 * Written: October 11, 2011
 *
 */

#ifndef __CTP_MOD_SCHEDULER_H_
#define __CTP_MOD_SCHEDULER_H_

#include "common/utils/common.h"

/* statistics structure */
struct ctp_mod_scheduler_stats
{
    unsigned long long      queued_bytes;
    unsigned long long      max_queued_bytes;

} __attribute((packed));

/* create an ethernet entity */
rv_t ctp_mod_scheduler_create(const char *name, handle_t sdu_pool, 
                              const unsigned int max_user_leftover, 
                              const unsigned int max_common_leftover,
                              handle_t *module);

#endif /* __CTP_MOD_SCHEDULER_H_ */

