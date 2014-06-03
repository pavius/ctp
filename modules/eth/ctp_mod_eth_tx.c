/* 
 * Ethernet transmitter module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <sys/socket.h>
#include <linux/types.h>
#include "modules/eth/ctp_mod_eth_tx_prv.h"
#include "modules/base/ctp_module_msgpool.h"

/* process a message */
void ctp_mod_eth_tx_process_message(struct ctp_module *module, 
                                    struct ctp_module_message *message)
{
    /* get the xmitter from module */
    struct ctp_mod_eth_tx *xmitter = (struct ctp_mod_eth_tx *)module;

    /* set external counters */
    xmitter->stats.tx_bytes += ctp_module_msg_get_bytes_written(message);
    xmitter->stats.tx_frames++;

    /* send outwards */
    send(xmitter->eth.socket, message->data, ctp_module_msg_get_bytes_written(message), 0);

    /* free the buffer */
    ctp_module_msgpool_free_msg(message);
}

/* create an ethernet entity */
rv_t ctp_mod_eth_tx_create(const char *name, const char *if_name, handle_t *module)
{
    rv_t result;
    struct ctp_mod_eth_tx *xmitter;

    /* create base object */
    result = ctp_mod_eth_create(sizeof(struct ctp_mod_eth_tx), 
                                CTP_MODTYPE_ETH_TX,
                                name, if_name, false, module);

    /* call base */
    if (result == RV_OK)
    {
        /* set xmitter stuff */
        xmitter = (struct ctp_mod_eth_tx *)(*module);
            ctp_module_set_process_message(xmitter, ctp_mod_eth_tx_process_message);
            ctp_module_register_stats(&xmitter->eth.module, 
                                      (unsigned char *)&xmitter->stats, 
                                      sizeof(xmitter->stats));

        /* create a socket */
        return ctp_mod_eth_socket_create(xmitter);
    }

    /* return the result */
    return result;
}

