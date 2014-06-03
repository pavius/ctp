/* 
 * Ethernet transmitter module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_ETH_TX_H_
#define __CTP_MOD_ETH_TX_H_

#include "common/utils/common.h"

/* statistics structure */
struct ctp_mod_eth_tx_stats
{
    unsigned long long      tx_frames;
    unsigned long long      tx_bytes;

} __attribute((packed));

/* create an ethernet entity */
rv_t ctp_mod_eth_tx_create(const char *name, const char *if_name, handle_t *module);

#endif /* __CTP_MOD_ETH_TX_H_ */

