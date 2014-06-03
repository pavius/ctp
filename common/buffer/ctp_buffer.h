/* 
 * Buffer pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 * 
 */

#ifndef __CTP_BUFFER_H_
#define __CTP_BUFFER_H_

#include "common/utils/data_struct.h"

/* buffer header */
struct ctp_buffer_header
{
    SIMPLEQ_ENTRY(ctp_buffer_header)   q_entry;    /* so that a buffer can be held in a queue   */
    handle_t                           q;          /* ptr to q from which buffer was alloc'd */
};

/* a buffer */
typedef void *ctp_buffer_t; 

#endif /* __CTP_BUFFER_H_ */
