/* 
 * Generator flow
 * Void (c) 2011 
 * 
 * Author: Eran Duchan
 * Written: November 11, 2011
 *
 */

#ifndef __CTP_MOD_GENERATOR_FLOW_H_
#define __CTP_MOD_GENERATOR_FLOW_H_

#include "common/utils/common.h"

/* create ip/udp */
void ctp_mod_generator_flow_create_ipv4_udp(handle_t generator,
                                            const char *eth_source, const char *eth_dest, 
                                            const unsigned int ip_source, const unsigned int ip_dest, 
                                            const unsigned short udp_source, const unsigned short udp_dest,
                                            const unsigned int pps, const unsigned int min_size, const unsigned int max_size);

/* create raw generator */
void ctp_mod_generator_flow_create_control(handle_t generator, struct ctp_config_user *user,
                                           const unsigned int pps, const unsigned int min_size, const unsigned int max_size);


#endif /* __CTP_MOD_GENERATOR_FLOW_H_ */

