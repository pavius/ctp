/* 
 * RLC receiver module
 * Receives frames and sends to registered modules
 *
 * Author: Eran Duchan <pavius@gmail.com>
 *
 */

#ifndef __CTP_MOD_ETH_RX_PRV_H_
#define __CTP_MOD_ETH_RX_PRV_H_

#include "modules/eth/ctp_mod_eth_rx.h"
#include "modules/eth/ctp_mod_eth_prv.h"

/* ethernet rx payload size */
#define CTP_MOD_ETH_RX_MAX_PAYLOAD_SZ (1514)

/* ethernet module */
struct ctp_mod_eth_rx
{
    struct ctp_mod_eth              eth;
    handle_t                        sdu_pool;
    struct ctp_mod_eth_rx_stats     stats;
    handle_t                        rx_frame_events;
    struct ctp_module_message       *sdu_message;
};

#endif /* __CTP_MOD_ETH_RX_PRV_H_ */
