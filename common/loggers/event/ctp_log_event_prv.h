/* 
 * High resolution event logger
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: August 20, 2011
 *
 */

#ifndef __CTP_LOG_EVENT_PRV_H_
#define __CTP_LOG_EVENT_PRV_H_

#include "common/loggers/event/ctp_log_event.h"

/* hr event log */
struct ctp_log_event
{
    char                                    name[128];
    unsigned char                           *events;
    unsigned int                            event_size;
    unsigned int                            max_events;
    unsigned int                            current_event_idx;
    ctp_log_event_to_file_callback_t        event_to_file;
    bool                                    accepting_events;
};

/* pointers to all open logs */
static struct 
{
    struct ctp_log_event *logs[16];
    unsigned int total_logs;
    unsigned int open_logs;

} ctp_log_event_logs = 
{
    .open_logs = 0,
    .total_logs = 0
};

/* register event */
void ctp_log_event_log_to_file(struct ctp_log_event *log);

/* close a log file */
void ctp_log_event_close(handle_t log_handle);

/* do the actual set */
#define ctp_log_event_event_by_index(log, index)                            \
    (log->events + (index * log->event_size))

#endif /* __CTP_LOG_EVENT_PRV_H_ */
