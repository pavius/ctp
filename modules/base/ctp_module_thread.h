/* 
 * Module thread
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_THREAD_H_
#define __CTP_MODULE_THREAD_H_

#include "modules/base/ctp_module.h"
#include <sched.h>

/* no affinity */
#define CTP_MODULE_THREAD_NO_AFFINITY (-1)

/* create a module thread */
rv_t ctp_module_thread_create(const int scheduling_mode,
                              const int scheduling_priority,
                              const int core_affinity,
                              handle_t *thread_handle);

/* attach an extra module to be polled */
rv_t ctp_module_thread_attach_module(handle_t thread_handle, 
                                     handle_t attached_module);

/* start a module thread */
rv_t ctp_module_thread_start(handle_t thread_handle);

#endif /* __CTP_MODULE_THREAD_H_ */
