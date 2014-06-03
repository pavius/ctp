/* 
 * Generator utility 
 * Void (c) 2011 
 * 
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_GENERATOR_PRV_H_
#define __CTP_MOD_GENERATOR_PRV_H_

#include "modules/generator/ctp_mod_generator.h"
#include "modules/generator/ctp_mod_generator_flow_prv.h"
#include "modules/base/ctp_module.h"

/* max flow count */
#define CTP_MOD_GENERATOR_MAX_FLOWS (128)

/* ethernet module */
struct ctp_mod_generator
{
    struct ctp_module               module;
    handle_t                        sdu_pool;
    unsigned int                    flow_count;
    struct ctp_mod_generator_flow   *flows[CTP_MOD_GENERATOR_MAX_FLOWS];
};

#endif /* __CTP_MOD_GENERATOR_PRV_H_ */
