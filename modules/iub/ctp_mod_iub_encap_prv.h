/* 
 * Iub encapsulation module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_IUB_ENCAP_PRV_H_
#define __CTP_MOD_IUB_ENCAP_PRV_H_

#include "modules/iub/ctp_mod_iub_encap.h"
#include "modules/base/ctp_module.h"

/* ethernet module */
struct ctp_mod_iub_encap
{
    struct ctp_module module;
};

/* static magic number to be inserted @ dest mac */
static unsigned int ctp_mod_iub_da_magic; 

#endif /* __CTP_MOD_IUB_ENCAP_PRV_H_ */
