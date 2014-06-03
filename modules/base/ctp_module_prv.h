/* 
 * Base object module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_PRV_H_
#define __CTP_MODULE_PRV_H_

#include "modules/base/ctp_module.h"

/* module names */
const char *CTP_MODULE_TYPE_NAMES[] =
{
    "Thread",
    "Queue",
    "Eth Rx",
    "Eth Tx",
    "Classifier",
    "RLC Seg",
    "RLC Ras",
    "Iub Encap",
    "Iub Decap",
    "Analyzer",
    "Scheduler",
    "Generator",
};

/* module id allocator */
static unsigned int ctp_module_next_free_id = 0;

/* total number of modules */
static unsigned int ctp_module_count = 0;

/* array holding the created modules */
struct ctp_module *ctp_created_modules[CTP_MODULE_MAX_MODULES];

#endif /* __CTP_MODULE_PRV_H_ */
