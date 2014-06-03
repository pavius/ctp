/* 
 * Buffer queue
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: October 10, 2011
 *
 */

#ifndef __CTP_BUFQ_H_
#define __CTP_BUFQ_H_

#include "common/utils/common.h"
#include "common/buffer/ctp_buffer.h"

/* init the buffer q */
rv_t ctp_bufq_create(handle_t *buf_q);

/* push a buffer onto the tail of the queue */
void ctp_bufq_push_tail(handle_t buf_q, ctp_buffer_t buffer);

/* pull a buffer from the head of the queue */
ctp_buffer_t ctp_bufq_pull_head(handle_t buf_q);

/* lock (busy wait) */
void ctp_bufq_lock(handle_t buf_q);

/* unlock (busy wait) */
void ctp_bufq_unlock(handle_t buf_q);

/* pending messages */
unsigned int ctp_bufq_buffer_count(handle_t buf_q);

#endif /* __CTP_BUFQ_H_ */
