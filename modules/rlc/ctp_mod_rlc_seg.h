/* 
 * RLC segmentation
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_RLC_SEG_H_
#define __CTP_MOD_RLC_SEG_H_

#include "common/utils/common.h"

/* rlc segmentation statistics */
struct ctp_mod_rlc_seg_stats
{
    unsigned long long      tx_pdus;
    unsigned long long      inputted_sdus;
    unsigned long long      inputted_bytes;

} __attribute((packed));

/* create an ethernet entity */
rv_t ctp_mod_rlc_seg_create(handle_t *module);

/* register a PDU pool */
void ctp_mod_rlc_seg_register_pdu_pool(handle_t module, 
                                       handle_t pdu_pool, 
                                       const unsigned int pdu_size);

#endif /* __CTP_MOD_RLC_SEG_H_ */

