/* 
 * High resolution event logger
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: August 20, 2011
 *
 */

#ifndef __CTP_LOG_EVENT_H_
#define __CTP_LOG_EVENT_H_

#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include "common/utils/common.h"

/* event to file callback */
typedef void (*ctp_log_event_to_file_callback_t)(FILE *, const void *);

/* init an event log */
void ctp_log_event_create(const char *name,
                          const unsigned int event_size,
                          const unsigned int max_events, 
                          const ctp_log_event_to_file_callback_t event_to_file,
                          handle_t *log_handle);

/* destroy an event log */
void ctp_log_event_destroy(handle_t log_handle);

/* register event */
void ctp_log_event_log_event(handle_t log_handle, const void *event);

/* register event with a timestamp */
void ctp_log_event_log_event_ts(handle_t log_handle, 
                                const void *event,
                                struct timespec *timestamp);

/* print status of logs */
void ctp_log_event_print_logs_status(void);

/* set members only if events enabled */
#ifdef CTP_EVENT_LOGS_ENABLED

    /* set an event field */
    #define ctp_log_event_set_field(field, value)       \
        field = value

#else

    /* do nothing */
    #define ctp_log_event_set_field(field, value)

#endif

#endif /* __CTP_LOG_EVENT_H_ */
