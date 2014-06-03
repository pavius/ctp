/* 
 * Base object module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdlib.h>
#include <string.h>
#include "common/utils/common.h"
#include "common/utils/assert.h"
#include "modules/base/ctp_module_thread_prv.h"

/* create a module thread */
rv_t ctp_module_thread_create(const int scheduling_mode,
                              const int scheduling_priority,
                              const int core_affinity,
                              handle_t *thread_handle)
{
    struct ctp_module_thread *thread;
    rv_t result;

    /* allocate structure */
    thread = malloc(sizeof(struct ctp_module_thread));
    bzero(thread, sizeof(*thread));

    /* check if allocated */
    if (thread == NULL)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_alloc_module_thread;
    }

    /* save params */
    thread->scheduling_mode     = scheduling_mode;
    thread->scheduling_priority = scheduling_priority;
    thread->core_affinity       = core_affinity;

    /* save handle */
    *thread_handle = thread;

    /* success */
    return RV_OK;

err_alloc_module_thread:
    return result;
}

/* attach an extra module to be polled */
rv_t ctp_module_thread_attach_module(handle_t thread_handle, 
                                     handle_t attached_module)
{
    struct ctp_module_thread *thread = (struct ctp_module_thread *)thread_handle;

    /* max sure there's room */
    ctp_assert((thread->attached_module_count + 1) < array_size(thread->attached_modules), 
               "Cannot attach any more modules to thread");

    /* do the attach */ 
    thread->attached_modules[thread->attached_module_count] = (struct ctp_module *)attached_module;

    /* increment attached count */
    thread->attached_module_count++;

    /* save ourselves in the module we're attaching to */
    ((struct ctp_module *)attached_module)->thread = (struct ctp_module *)thread;

    /* return ok */
    return RV_OK;
}

/* wrapper for module entry */
void* ctp_module_thread_entry(void *data)
{
    /* get the thread */
    struct ctp_module_thread *thread = (struct ctp_module_thread *)data;

/* for simulation */
#ifndef CTP_SIMULATION

    /* set sched params */
    struct sched_param sp = 
    {
        .__sched_priority = thread->scheduling_priority
    };

    /* do we need to set affinity? */
    if (thread->core_affinity != CTP_MODULE_THREAD_NO_AFFINITY)
    {
        cpu_set_t mask;

        /* init mask */
        CPU_ZERO(&mask);

        /* set the mask */
        CPU_SET(thread->core_affinity, &mask);

        /* set affinity */
        ctp_assert(sched_setaffinity(0, sizeof(mask), &mask) == 0, "Failed to set affinity");
    }

    /* set scheduling mode */
    ctp_assert(sched_setscheduler(0, thread->scheduling_mode, &sp) == 0, 
               "Failed to set scheduler. sched(%d) pri(%d)", 
               thread->scheduling_mode,
               sp.__sched_priority);

#endif

    /* poll forever (TODO: poll return exit value) */
    while (1)
    {
        unsigned int module_idx; 

        for (module_idx = 0; 
              module_idx < thread->attached_module_count; 
              ++module_idx)
        {
            /* get the module */
            struct ctp_module *module = thread->attached_modules[module_idx];

            /* call its poll function */
            module->poll(module);
        }
    }

	/* done */
	return NULL;
}

/* start a module thread */
rv_t ctp_module_thread_start(handle_t thread_handle)
{
    struct ctp_module_thread *thread = (struct ctp_module_thread *)thread_handle;

    /* start thread */
    if (pthread_create(&thread->thread_handle, NULL, ctp_module_thread_entry, thread) == 0)
    {
        /* done */
        return RV_OK;
    }
    else
    {
        /* failed */
        return RV_ERR_CANT_CREATE;
    }
}

