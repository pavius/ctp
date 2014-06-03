/* 
 * RLC reassembly module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_RLC_RAS_PRV_H_
#define __CTP_MOD_RLC_RAS_PRV_H_

#include "modules/rlc/ctp_mod_rlc_ras.h"
#include "modules/base/ctp_module.h"

/* ethernet module */
struct ctp_mod_rlc_ras
{
    struct ctp_module               module;
    handle_t                        sdu_pool;
};

#endif /* __CTP_MOD_RLC_RAS_PRV_H_ */
