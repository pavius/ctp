/* 
 * Ethernet interface module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_ETH_H_
#define __CTP_MOD_ETH_H_

#include <stdbool.h>
#include "common/utils/common.h"

/* create an ethernet entity */
rv_t ctp_mod_eth_create(const unsigned int module_desc_size, 
                        const enum ctp_module_type type, 
                        const char *name, const char *if_name, 
                        const bool promisc, handle_t *module);

/* create a socket over an interface */
rv_t ctp_mod_eth_socket_create(handle_t module);

/* create a ring over an interface */
rv_t ctp_mod_eth_ring_create(handle_t module);

/* set promiscuous mode */
rv_t ctp_mod_eth_set_promisc(handle_t module, bool promisc);

#endif /* __CTP_MOD_ETH_H_ */

