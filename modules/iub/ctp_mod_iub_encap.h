/* 
 * Iub encapsulation module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_IUB_ENCAP_H_
#define __CTP_MOD_IUB_ENCAP_H_

#include "common/utils/common.h"

/* constant to be inserted @ dest MAC 4 MSBs to indicate classified */
#define CTP_MOD_IUB_CLASSIFIED_FRAME_MAGIC (0x0000FFFF)

/* create an ethernet entity */
rv_t ctp_mod_iub_encap_create(handle_t *module);

#endif /* __CTP_MOD_IUB_ENCAP_H_ */

