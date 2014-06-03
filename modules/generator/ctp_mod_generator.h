/* 
 * Generator utility 
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_GENERATOR_H_
#define __CTP_MOD_GENERATOR_H_

#include "common/utils/common.h"

/* create an ethernet entity */
rv_t ctp_mod_generator_create(handle_t *module, 
                              const char *name, 
                              handle_t sdu_pool);

/* register a flow on a generator */
void ctp_mod_generator_register_flow(handle_t module, handle_t flow);

#endif /* __CTP_MOD_GENERATOR_H_ */

