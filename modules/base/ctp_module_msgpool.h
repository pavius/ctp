/* 
 * Module message pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_MSGPOOL_H_
#define __CTP_MODULE_MSGPOOL_H_

#include "common/utils/common.h"
#include "modules/base/ctp_module.h"

/* init the message pool */
rv_t ctp_module_msgpool_create(const unsigned int max_data_length,
                               const unsigned int initial_messages,
                               handle_t *msg_pool);

/* allocate message */
struct ctp_module_message* ctp_module_msgpool_alloc_msg(handle_t msg_pool);

/* free message */
void ctp_module_msgpool_free_msg(struct ctp_module_message *message);

#endif /* __CTP_MODULE_MSGPOOL_H_ */
