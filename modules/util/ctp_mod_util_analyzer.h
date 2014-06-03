/* 
 * Analyzer utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_UTIL_ANALYZER_H_
#define __CTP_MOD_UTIL_ANALYZER_H_

#include "common/utils/common.h"

/* statistics structure */
struct ctp_mod_util_analyzer_stats
{
    unsigned long long      rx_frames;
    unsigned long long      rx_bytes;

} __attribute((packed));

/* analyzer header */
struct ctp_mod_util_analyzer_header
{
    unsigned int seqnum;
    unsigned int crc;

} __attribute((packed));

/* create an ethernet entity */
rv_t ctp_mod_util_analyzer_create(handle_t *module);

#endif /* __CTP_MOD_UTIL_ANALYZER_H_ */

