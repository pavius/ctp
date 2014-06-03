/* 
 * RLC receiver module
 * Receives frames and sends to registered modules
 *
 * Author: Eran Duchan <pavius@gmail.com>
 *
 */

#ifndef __CTP_MOD_ETH_PRV_H_
#define __CTP_MOD_ETH_PRV_H_

#include "modules/base/ctp_module.h"
#include "modules/eth/ctp_mod_eth.h"
#include <pf_ring/pfring.h>

/* max name size */
#define CTP_MOD_IF_MAX_NAME_SZ (64)

/* ethernet module */
struct ctp_mod_eth
{
    struct ctp_module               module;
    char                            interface_name[CTP_MOD_IF_MAX_NAME_SZ];
    int		                        socket;
    pfring                          *ring;
};

#endif /* __CTP_MOD_ETH_PRV_H_ */
