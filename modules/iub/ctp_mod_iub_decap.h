/* 
 * Iub decapsulation module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_IUB_DECAP_H_
#define __CTP_MOD_IUB_DECAP_H_

#include "common/utils/common.h"

/* iub decapsulation statistics */
struct ctp_mod_iub_decap_stats
{
    unsigned long long not_enough_data_l2; /* not enough bytes in packet for L2 header */
    unsigned long long oos_frames;
    unsigned long long possibly_reordered_frames;

} __attribute((packed));

/* create an iub decapsulation entity */
rv_t ctp_mod_iub_decap_create(handle_t *module);

#endif /* __CTP_MOD_IUB_DECAP_H_ */

