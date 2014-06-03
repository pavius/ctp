/* 
 * In memory event logger
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: October 21, 2011
 *
 */

#include <string.h>
#include "common/loggers/event/ctp_log_event_prv.h"
#include "common/utils/assert.h"

/* init an event log */
void ctp_log_event_create(const char *name,
                          const unsigned int event_size,
                          const unsigned int max_events,
                          const ctp_log_event_to_file_callback_t event_to_file,
                          handle_t *log_handle)
{
/* only when logs are enabled */
#ifdef CTP_EVENT_LOGS_ENABLED

    /* the log */
    struct ctp_log_event *log = malloc(sizeof(struct ctp_log_event));
    ctp_assert(log != NULL, "Failed to allocate %s hr event log", name);

    /* zero out the log */
    bzero(log, sizeof(*log));

    /* allocate events */
    log->events = malloc(event_size * max_events);
    ctp_assert(log->events != NULL, "Failed to allocate %s hr event log events", name);

    /* save members */
    safe_strncpy(log->name, name, sizeof(log->name));
    log->max_events         = max_events;
    log->accepting_events   = true;
    log->event_size         = event_size;
    log->event_to_file      = event_to_file;

    /* register the open log */
    ctp_log_event_logs.logs[ctp_log_event_logs.total_logs] = log;
    ctp_log_event_logs.total_logs++;
    ctp_log_event_logs.open_logs++;

    /* return log */
    *log_handle = log;

#else

    /* nullify the handle */
    *log_handle = NULL;

#endif
}

/* destroy an event log */
void ctp_log_event_destroy(handle_t log_handle)
{
    /* get log */
    struct ctp_log_event *log = (struct ctp_log_event *)log_handle;

    /* free the log */
    if (log->events) free(log);
    free(log);
}

/* dump log to file */
void ctp_log_event_to_file(struct ctp_log_event *log)
{
    unsigned int event_idx;

    /* out */
    printf("Saving %s log ... ", log->name);

    /* open the log file */
    FILE *log_file = fopen(log->name, "w+");
    ctp_assert(log_file != NULL, "Failed to open log file");

    /* dump events */
    for (event_idx = 0; event_idx < log->max_events; ++event_idx)
    {
        /* output the event to the log */
        log->event_to_file(log_file, ctp_log_event_event_by_index(log, event_idx));
    }

    /* close file */
    fclose(log_file);

    /* out */
    printf("Done.\n");
}

/* close a log file */
void ctp_log_event_close(handle_t log_handle)
{
    /* get log */
    struct ctp_log_event *log = (struct ctp_log_event *)log_handle;

    /* make sure its open */
    ctp_assert(log->accepting_events, "Tried to close closed log");

    /* set its flag */
    log->accepting_events = false;

    /* decrement total open logs and check if all have closed */
    if (--ctp_log_event_logs.open_logs == 0)
    {
        unsigned int log_idx;

        /* iterate over all logs and dump them to file */
        for (log_idx = 0; log_idx < ctp_log_event_logs.total_logs; ++log_idx)
        {
            /* make sure its open */
            ctp_assert(!ctp_log_event_logs.logs[log_idx]->accepting_events, 
                       "Log is still open, can't save");

            /* save it to file */
            ctp_log_event_to_file(ctp_log_event_logs.logs[log_idx]);
        }

        /* done - exit */
        ctp_assert(0, "All event logs are full. Exiting");
    }
}

/* register event */
void ctp_log_event_log_event(handle_t log_handle, const void *event)
{
    /* get log */
    struct ctp_log_event *log = (struct ctp_log_event *)log_handle;

    /* do nothing if not accepting events */
    if (log_handle == NULL || !log->accepting_events) return;

    /* log the event */
    memcpy(ctp_log_event_event_by_index(log, log->current_event_idx), event, log->event_size);

    /* next item */
    log->current_event_idx++;

    /* if no more space, log and exit */
    if (log->current_event_idx >= log->max_events)
    {
        /* close the log. if it's the last open log we exit */
        ctp_log_event_close(log);
    }
}

/* get current entry */
void* ctp_log_event_next_event(handle_t log_handle)
{
    /* get log */
    struct ctp_log_event *log = (struct ctp_log_event *)log_handle;

    /* do nothing if not accepting events */
    if (log_handle == NULL || !log->accepting_events) return NULL;

    /* do we have space for another? */
    if ((log->current_event_idx + 1) < log->max_events)
    {
    	/* get current entry */
    	void *entry = ctp_log_event_event_by_index(log, log->current_event_idx);

        /* inc index */
        log->current_event_idx++;

        /* return it */
        return entry;
    }
    else
    {
        /* dump the log to file */
        ctp_log_event_close(log_handle);

        /* and crash */
        ctp_assert(0, "Filled up scheduler log");
    }
}

/* register event with a timestamp */
void ctp_log_event_log_event_ts(handle_t log_handle, 
                                const void *event,
                                struct timespec *timestamp)
{
    /* get log */
    struct ctp_log_event *log = (struct ctp_log_event *)log_handle;

    /* do nothing if not accepting events */
    if (log_handle == NULL || !log->accepting_events) return;

    /* get current time */
    clock_gettime(CLOCK_MONOTONIC, timestamp);

    /* register the event */
    ctp_log_event_log_event(log_handle, event);
}

/* print status of logs */
void ctp_log_event_print_logs_status(void)
{
    unsigned int log_idx;

    /* iterate over all logs and dump them to file */
    for (log_idx = 0; log_idx < ctp_log_event_logs.total_logs; ++log_idx)
    {
        /* save it to file */
        printf("%s log: %d of %d\n", 
               ctp_log_event_logs.logs[log_idx]->name,
               ctp_log_event_logs.logs[log_idx]->current_event_idx,
               ctp_log_event_logs.logs[log_idx]->max_events);
    }
}

