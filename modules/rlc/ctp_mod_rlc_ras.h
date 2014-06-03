/* 
 * RLC reassembly module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_RLC_RAS_H_
#define __CTP_MOD_RLC_RAS_H_

#include "common/utils/common.h"

/* rlc segmentation statistics */
struct ctp_mod_rlc_ras_stats
{
    unsigned long long      rx_pdus;
    unsigned long long      oos_pdus;            /* out of sequence */
    unsigned long long      not_enough_data_pdu; /* not enough bytes in packet for a pdu */
    unsigned long long      invalid_pdu_size;    /* pdu size exceeds user fragment */

} __attribute((packed));

/* create an rlc reassembly entity */
rv_t ctp_mod_rlc_ras_create(handle_t sdu_pool, handle_t *module);

#endif /* __CTP_MOD_RLC_RAS_H_ */

