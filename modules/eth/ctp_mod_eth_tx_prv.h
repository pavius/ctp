/* 
 * Ethernet transmitter module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_ETH_TX_PRV_H_
#define __CTP_MOD_ETH_TX_PRV_H_

#include "modules/eth/ctp_mod_eth_tx.h"
#include "modules/eth/ctp_mod_eth_prv.h"

/* ethernet module */
struct ctp_mod_eth_tx
{
    struct ctp_mod_eth              eth;
    struct ctp_mod_eth_tx_stats     stats;
    handle_t                        tx_frame_events;
};

#endif /* __CTP_MOD_ETH_TX_PRV_H_ */
