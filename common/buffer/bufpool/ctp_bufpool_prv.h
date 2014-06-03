/* 
 * Module message pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_BUFPOOL_PRV_H_
#define __CTP_BUFPOOL_PRV_H_

#include "common/buffer/bufpool/ctp_bufpool.h"

/* a pool */
struct ctp_bufpool
{
    handle_t                q;
};

#endif /* __CTP_BUFPOOL_PRV_H_ */
