/* 
 * Ethernet interface module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "modules/eth/ctp_mod_eth_prv.h"
#include "common/utils/assert.h"

/* create a ring over an interface */
rv_t ctp_mod_eth_ring_create(handle_t module)
{
    u_int32_t ring_drv_info;

    /* get eth module */
    struct ctp_mod_eth *eth_module = (struct ctp_mod_eth *)module;

    /* create a pf_ring */
    eth_module->ring = pfring_open(eth_module->interface_name, 1, 1514, 0);

    /* check created */
    ctp_assert(eth_module->ring!= NULL, "Failed to create ring");

    /* Print PF_RING driver version */
    pfring_version(eth_module->ring, &ring_drv_info);

    /* set the application name */
    pfring_set_application_name(eth_module->ring, "ctp-rx");

    /* enable the ring */
    pfring_enable_ring(eth_module->ring);

    /* success */
    return RV_OK;
}

/* create a socket over an interface */
rv_t ctp_mod_eth_socket_create(handle_t module)
{
    int new_socket;
    rv_t result;
    struct sockaddr_ll sock_address;
    struct ifreq eth_request;

    /* get eth module */
    struct ctp_mod_eth *eth_module = (struct ctp_mod_eth *)module;

    /* try to create the socket */
    new_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* check */
    if (new_socket < 0)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_sock_create;
    }

    /* get interface info */
    bzero(&eth_request, sizeof(eth_request));
        safe_strncpy(eth_request.ifr_ifrn.ifrn_name, eth_module->interface_name, sizeof(eth_request.ifr_ifrn.ifrn_name));

    /* try to get the interface info */
    if (ioctl(new_socket, SIOCGIFINDEX, &eth_request) == -1)
    {
    	char *err_str = strerror(errno);

        /* error */
        result = RV_ERR_SOCKET;
        goto err_sock_get_if_fdx;
    }

    /* bind to specific interface */
    bzero(&sock_address, sizeof(sock_address));
        sock_address.sll_family     = AF_PACKET;
        sock_address.sll_ifindex    = eth_request.ifr_ifindex;
        sock_address.sll_protocol   = htons(ETH_P_ALL);

    /* bind the socket to the interface */    
    if (bind(new_socket, (struct sockaddr *)&sock_address, sizeof(sock_address)) == -1) 
    {
        /* error */
        result = RV_ERR_SOCKET;
        goto err_sock_get_bind;
    }

    /* save the socket */
    eth_module->socket = new_socket;

    /* success */
    return RV_OK;

/* error */
err_sock_get_bind:
err_sock_get_if_fdx:
    close(new_socket);
err_sock_create:
    return result;
}

/* set promiscuous mode */
rv_t ctp_mod_eth_set_promisc(handle_t module, bool promisc) 
{
    int sock_fd;
    struct ifreq ifr;
    
    /* get eth module */
    struct ctp_mod_eth *eth_module = (struct ctp_mod_eth *)module;

    /* open teh socket */    
    sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* check success */
    if (sock_fd <= 0) return RV_ERR_CANT_OPEN;
    
    /* zero out the flags */
    memset(&ifr, 0, sizeof(ifr));

    /* copy the name */
    safe_strncpy(ifr.ifr_name, eth_module->interface_name, sizeof(ifr.ifr_name));

    /* try ioctl, getting flags */
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) 
    {
        /* clean up and exit */
        close(sock_fd);
        return RV_ERR_SOCKET;
    }
    
    /* set or clear the flag */
    if (promisc)    ifr.ifr_flags |= IFF_PROMISC;
    else            ifr.ifr_flags &= ~IFF_PROMISC;
    
    /* and set it back to the socket */
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        /* clean up */
        close(sock_fd);
        return RV_ERR_SOCKET;
    }
    
    /* we're done, close the socket */
    close(sock_fd);

    /* sucess */
    return RV_OK;
}

/* create a receiver */
rv_t ctp_mod_eth_create(const unsigned int module_desc_size, 
                        const enum ctp_module_type type, 
                        const char *name, const char *if_name, 
                        const bool promisc, handle_t *module)
{
    rv_t result;
    struct ctp_mod_eth *eth_module;

    /* call base */
    result = ctp_module_create(module_desc_size, type, name, module);

    /* ethernet module */
    eth_module = *module;

    /* if success */
    if (result == RV_OK)
    {
        /* copy interface name and such */
        safe_strncpy(eth_module->interface_name, if_name, sizeof(eth_module->interface_name));
    }
    else
    {
        /* return whatever error */
        return result;
    }

    /* success */
    return RV_OK;
}

