/* 
 * Generator flow
 * Void (c) 2011 
 * 
 * Author: Eran Duchan
 * Written: November 11, 2011
 *
 */

#ifndef __CTP_MOD_GENERATOR_FLOW_PRV_H_
#define __CTP_MOD_GENERATOR_FLOW_PRV_H_

#include "modules/generator/ctp_mod_generator.h"
#include "modules/base/ctp_module.h"

/* ethernet module */
struct ctp_mod_generator_flow
{
    struct ctp_mod_generator          *generator;
    struct timespec                   next_tx_time;
    unsigned int                      ifg;        /* inter frame gap */
    unsigned int                      min_size;
    unsigned int                      max_size;
    unsigned char                     header[512];
    unsigned int                      header_size;
    unsigned int                      total_header_size;
    unsigned int                      trailer_size;
    unsigned int                      seqnum;
    unsigned int                      next_tx_size;
    struct ctp_config_user            *user;
    rv_t                              (*on_before_tx)(struct ctp_mod_generator_flow *, 
                                                      struct ctp_module_message *);
};

#endif /* __CTP_MOD_GENERATOR_FLOW_PRV_H_ */
