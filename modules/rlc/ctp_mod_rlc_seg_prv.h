/* 
 * RLC segmentation
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_RLC_SEG_PRV_H_
#define __CTP_MOD_RLC_SEG_PRV_H_

#include "modules/rlc/ctp_mod_rlc_seg.h"
#include "modules/base/ctp_module.h"

/* max supported frag size */
#define CTP_MOD_RLC_MAX_FRAG_SZ (512)

/* max number of PDUS to be shoved into a single frame */
#define CTP_MOD_RLC_MAX_PDUS_PER_FRAME (31)

/* max number of pdu pools */
#define CTP_MOD_RLC_MAX_PDU_POOLS (2)

/* pdu pool definition */
struct ctp_mod_rlc_seg_pdu_pool
{
    unsigned int    pdu_size;
    handle_t        pdu_pool;
};

/* ethernet module */
struct ctp_mod_rlc_seg
{
    struct ctp_module               module;
    unsigned char                   padding_sequence[CTP_MOD_RLC_MAX_FRAG_SZ];
    struct ctp_mod_rlc_seg_pdu_pool pdu_pools[CTP_MOD_RLC_MAX_PDU_POOLS]; /* for data pdus      */
};

#endif /* __CTP_MOD_RLC_SEG_PRV_H_ */
