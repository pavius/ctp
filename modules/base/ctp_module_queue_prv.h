/* 
 * Module message queue
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_QUEUE_PRV_H_
#define __CTP_MODULE_QUEUE_PRV_H_

#include "modules/base/ctp_module_queue.h"
#include "modules/base/ctp_module.h"
#include <pthread.h>

/* module message queue */
struct ctp_module_queue
{
    struct ctp_module               module;
    struct ctp_module_msgq          msgq;
    pthread_spinlock_t		        msgq_lock;
    struct ctp_module_queue_stats   stats;
};

#endif /* __CTP_MODULE_QUEUE_PRV_H_ */
