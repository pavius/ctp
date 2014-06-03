/* 
 * Module message queue
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_QUEUE_H_
#define __CTP_MODULE_QUEUE_H_

#include "common/utils/common.h"

/* statistics structure */
struct ctp_module_queue_stats
{
    unsigned int            msgq_message_count;
    unsigned int            msgq_high_watermark;

} __attribute((packed));

/* create a module queue */
rv_t ctp_module_queue_create(handle_t *module);

/* attach the queue to a module */
rv_t ctp_module_queue_attach_module(handle_t queue, handle_t module);

#endif /* __CTP_MODULE_QUEUE_H_ */
