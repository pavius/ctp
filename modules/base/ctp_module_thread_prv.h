/* 
 * Base object module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __RLC_MODULE_THREAD_PRV_H_
#define __RLC_MODULE_THREAD_PRV_H_

#include <pthread.h>
#include "modules/base/ctp_module_thread.h"

/* max number of attached modules */
#define CTP_MODULE_THREAD_MAX_ATTACHED_MODULES (8)

/* a thread that can run any number of modules */
struct ctp_module_thread
{
    struct ctp_module   *attached_modules[CTP_MODULE_THREAD_MAX_ATTACHED_MODULES]; 
    unsigned int        attached_module_count;
    pthread_t           thread_handle;
    int                 scheduling_mode;
    int                 scheduling_priority;
    int                 core_affinity;
};

#endif /* __RLC_MODULE_THREAD_PRV_H_ */
