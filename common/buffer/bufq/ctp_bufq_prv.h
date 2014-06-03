/* 
 * Buffer queue
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: October 10, 2011
 *
 */

#ifndef __CTP_BUFQ_PRV_H_
#define __CTP_BUFQ_PRV_H_

#include "common/buffer/bufq/ctp_bufq.h"
#include "common/utils/data_struct.h"

/* define a queue of buffers */
SIMPLEQ_HEAD(ctp_buffer_q, ctp_buffer_header);

/* a queue */
struct ctp_bufq
{
    struct ctp_buffer_q     buf_q;
    pthread_spinlock_t      lock;
    unsigned int            queued_buffers; /* number of buffers in queue */
};

#endif /* __CTP_BUFQ_PRV_H_ */
