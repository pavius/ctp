/* 
 * Buffer pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 * 
 */

#ifndef __CTP_BUFPOOL_H_
#define __CTP_BUFPOOL_H_

#include "common/utils/common.h"
#include "common/buffer/ctp_buffer.h"

/* init the buffer pool */
rv_t ctp_bufpool_create(const unsigned int max_data_length,
                        const unsigned int initial_messages,
                        void (*message_init_callback)(void *, ctp_buffer_t),
                        void *callback_arg,
                        handle_t *buf_pool);

/* allocate message */
ctp_buffer_t ctp_bufpool_alloc_buf(handle_t buf_pool);

/* free message */
void ctp_bufpool_free_buf(ctp_buffer_t buffer);

#endif /* __CTP_MODULE_MSGPOOL_H_ */
