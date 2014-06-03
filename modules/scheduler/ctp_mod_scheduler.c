/* 
 * Ethernet scheduler module
 * Void (c) 2011
 *
 * Author: Eran Duchan
 * Written: October 11, 2011
 *
 */

#include <string.h>
#include "modules/scheduler/ctp_mod_scheduler_prv.h"
#include "common/utils/assert.h"
#include "config/ctp_config_user.h"
#include "config/ctp_config.h"
#include "common/loggers/event/ctp_log_event.h"

/* output the event to the log */
void ctp_mod_scheduler_event_to_file(FILE *log_file, const void *event)
{
    char str_buffer[256];

    /* point to the event */
    struct ctp_mod_scheduler_log_entry *entry = (struct ctp_mod_scheduler_log_entry *)event;

    /* dump by type */
    switch (entry->type)
    {
        /* nodeb */
        case CTP_MOD_SCHEDULER_LOG_ET_NODEB:

            /* print node-b */
            fprintf(log_file, "nodeb: users(%d) before-lo(%d) after-lo(%d) per-user-alloc(%d)\n", 
                    entry->data.nodeb.active_user_cout,
                    entry->data.nodeb.before_common_leftover,
                    entry->data.nodeb.after_common_leftover,
                    entry->data.nodeb.per_user_allocation);

            break;

        /* user */
        case CTP_MOD_SCHEDULER_LOG_ET_USER:

            /* print node-b */
            fprintf(log_file, "\t[%s] before-lo(%d) before-bytes-q(%d) total-given(%d) unused(%d) after-lo(%d) after-bytes-q(%d)\n", 
                    ip_addr_to_str(entry->data.user.idx, str_buffer, sizeof(str_buffer)),
                    entry->data.user.before_leftover,
                    entry->data.user.before_bytes_in_queue,
                    entry->data.user.total_given,
                    entry->data.user.unused,
                    entry->data.user.after_leftover,
                    entry->data.user.after_bytes_in_queue);

            break;

        /* schedule */
        case CTP_MOD_SCHEDULER_LOG_ET_SCHEDULE:

            /* print node-b */
            fprintf(log_file, "============= Schedule # %d ============= \n", 
                    entry->data.schedule.index);

            break;
    }
}

void ctp_mod_scheduler_sleep(struct timespec *prev_wakeup_time)
{
/* busy wait */
#if 1

    struct timespec start, now, diff;

    /* get current time */
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* */
    while (1)
    {
        /* get current time */
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* diff with start time */
        timespec_diff(&start,
                      &now,
                      &diff);

        /* if greater than 10ms, break */
        if (diff.tv_nsec > 10000000)
        {
            /* set wakeup time */
            *prev_wakeup_time = now;

            break;
        }
    }   

/* sleep wait */
#else

    /* sleep wait */
    usleep(10000);

#endif
}

/* send messages out to next module */
void ctp_mod_scheduler_send_messages(struct ctp_mod_scheduler *scheduler,
                                     struct ctp_module_message *messages[],
                                     const unsigned int message_count)
{
    unsigned int message_idx;

    /* iterate over the messages we need to send */
    for (message_idx = 0; message_idx < message_count; ++message_idx)
    {
        /* forward the message */
        ctp_module_forward_message(scheduler, messages[message_idx]);
    }
}

/* scheduler function */
void ctp_mod_scheduler_poll(struct ctp_module *module)
{
    struct timespec prev_wakeup_time;
    struct log_entry;
    unsigned int schedule_index = 0;

    /* get scheduler */
    struct ctp_mod_scheduler *scheduler = (struct ctp_mod_scheduler *)module;

    /* point to stats */
    struct ctp_mod_scheduler_stats *stats = (struct ctp_mod_scheduler_stats *)scheduler->module.stats;

    /* initialize the previous time the scheduler woke up */
    clock_gettime(CLOCK_MONOTONIC, &prev_wakeup_time);

    /* forever */
    while (1)
    {
        struct timespec now;
        struct ctp_config_nodeb *nodeb;
        struct ctp_mod_scheduler_log_entry_nodeb *nodeb_log;

        /* sleep tti */
        ctp_mod_scheduler_sleep(&prev_wakeup_time);

        /* create a log entry for the nodeb */
        struct ctp_mod_scheduler_log_entry *sched_log = (struct ctp_mod_scheduler_log_entry *)ctp_log_event_next_event(scheduler->log);

        /* set sched index */
        ctp_log_event_set_field(sched_log->type, CTP_MOD_SCHEDULER_LOG_ET_SCHEDULE);
        ctp_log_event_set_field(sched_log->data.schedule.index, schedule_index++);

        /* iterate over all nodeBs */
        TAILQ_FOREACH(nodeb, &ctp_config_get()->nodeb_list, config_entry)
        {
            unsigned int active_user_count;

            /* lock the nodeb - any queues that become active from now on will only be scheduled next tti */
            ctp_config_nodeb_lock_for_scheduling(nodeb, &now);

            /* get active user count */
            active_user_count = nodeb->current_tti_active_user_qs->count;

            /* any active queues? */
            if (active_user_count)
            {
                struct ctp_config_user *active_user;

                /* create a log entry for the nodeb */
                struct ctp_mod_scheduler_log_entry *nodeb_log = (struct ctp_mod_scheduler_log_entry *)ctp_log_event_next_event(scheduler->log);

                /* calculate the number of credits per user, taking into account the previous common credit leftover */
                unsigned int per_user_credits = ((nodeb->max_bandwidth_bp_tti + nodeb->common_leftover_credits) / active_user_count);

                /* set log */
                ctp_log_event_set_field(nodeb_log->type, CTP_MOD_SCHEDULER_LOG_ET_NODEB);
                ctp_log_event_set_field(nodeb_log->data.nodeb.time, now);
                ctp_log_event_set_field(nodeb_log->data.nodeb.before_common_leftover, nodeb->common_leftover_credits);
                ctp_log_event_set_field(nodeb_log->data.nodeb.active_user_cout, active_user_count);
                ctp_log_event_set_field(nodeb_log->data.nodeb.per_user_allocation, per_user_credits);

                /* zero out common credits */
                nodeb->common_leftover_credits = 0;
                
                /* iterate over all active user queues in the nodeB */
                while ((active_user = ctp_config_nodeb_pop_active_user(nodeb, nodeb->current_tti_active_user_qs)) != NULL)
                {
                    struct ctp_module_message *output_messages[CTP_MOD_SCHEDULER_MAX_FRAMES_PER_TTI];
                    unsigned int output_message_count;
                    unsigned int remaining_queued_bytes, unused_credit_count, bytes_in_q_before_pull;

                    /* create a log entry for the nodeb */
                    struct ctp_mod_scheduler_log_entry *user_log = (struct ctp_mod_scheduler_log_entry *)ctp_log_event_next_event(scheduler->log);

                    /* calculate the total amount of credits for this specific user according to
                     * per_user_credits (tti credits + common leftover) plus the amount of per-user leftover
                     * credits from the previous active TTI for this specific user 
                     */ 
                    unsigned int total_user_credit = (per_user_credits + active_user->pdu_q_leftover_credits);

                    /* set log */
                    ctp_log_event_set_field(user_log->type, CTP_MOD_SCHEDULER_LOG_ET_USER);
                    ctp_log_event_set_field(user_log->data.user.idx, active_user->ip_addr);
                    ctp_log_event_set_field(user_log->data.user.before_leftover, active_user->pdu_q_leftover_credits);
                    ctp_log_event_set_field(user_log->data.user.total_given, total_user_credit);
             
                    /* lock the user-queue - if a pdu is going to be received, it will have to wait for us to finish */
                    ctp_config_user_q_lock(active_user);

                    /* pull as much data as is permitted by total_user_credit and receive how much
                     * credits are left after the send. may span over multiple messages - this will be 
                     * shoved into an array and the number of messages returned 
                     */
                    ctp_config_user_q_pull_pdus(active_user, 
                                                total_user_credit, 
                                                scheduler->sdu_pool,
                                                output_messages, 
                                                array_size(output_messages),
                                                &output_message_count,
                                                &bytes_in_q_before_pull,
                                                &unused_credit_count, 
                                                &remaining_queued_bytes);

                    /* update user statistics */
                    stats[active_user->index].queued_bytes      = ctp_bufq_buffer_count(active_user->pdu_q);
                    stats[active_user->index].max_queued_bytes  = get_maximum(stats[active_user->index].queued_bytes,
                                                                              stats[active_user->index].max_queued_bytes);

                    /* if the queue has data remaining */
                    if (remaining_queued_bytes)
                    {
                        /* add this user-queue the list of node-b active queues. because the node-b is locked for
                         * scheduling it will be added to the list of queues for the next tti. keep the state
                         * of the queue as "active"
                         */
                        ctp_config_nodeb_add_active_user_q(nodeb, active_user);
                    }
                    else 
                    {
                        /* set the queue to inactive state */
                        active_user->pdu_q_state = CTP_CONFIG_USER_Q_STATE_INACTIVE;
                    }

                    /* unlock the queue */ 
                    ctp_config_user_q_unlock(active_user);

                    /* keep whatever is below the threshold in the per-user storage
                     * Important note: does not accumulate per-user, overrides previous
                     */
                    active_user->pdu_q_leftover_credits = get_minimum(unused_credit_count, scheduler->max_user_leftover);

                    /* set log */
                    ctp_log_event_set_field(user_log->data.user.before_bytes_in_queue, bytes_in_q_before_pull);
                    ctp_log_event_set_field(user_log->data.user.after_leftover, active_user->pdu_q_leftover_credits);
                    ctp_log_event_set_field(user_log->data.user.after_bytes_in_queue, remaining_queued_bytes);
                    ctp_log_event_set_field(user_log->data.user.unused, unused_credit_count);

                    /* add credits above a certain threshold (MAX_PER_USER_LEFTOVER) to a per-nodeB common leftover counter */
                    nodeb->common_leftover_credits += get_maximum(0, (int)unused_credit_count - (int)scheduler->max_user_leftover);

                    /* send the array of messages onwards */
                    ctp_mod_scheduler_send_messages(scheduler, output_messages, output_message_count);
                }

                /* make sure the common leftover credits doesn't exceed a certain threshold */
                nodeb->common_leftover_credits = get_minimum(nodeb->common_leftover_credits, scheduler->max_common_leftover);

                /* set log */
                ctp_log_event_set_field(nodeb_log->data.nodeb.after_common_leftover, nodeb->common_leftover_credits);
            }

            /* unlock the node-b */
            ctp_config_nodeb_unlock_for_scheduling(nodeb);
        }
    }
}

/* create an ethernet entity */
rv_t ctp_mod_scheduler_create(const char *name, handle_t sdu_pool, 
                              const unsigned int max_user_leftover, 
                              const unsigned int max_common_leftover,
                              handle_t *module)
{
    rv_t result;
    struct ctp_mod_scheduler *scheduler;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_scheduler), 
                               CTP_MODTYPE_SCHEDULER, name, module);

    /* call base */
    if (result == RV_OK)
    {
        /* set scheduler stuff */
        scheduler = (struct ctp_mod_scheduler *)(*module);
            scheduler->module.poll              = ctp_mod_scheduler_poll;
            scheduler->sdu_pool                 = sdu_pool;
            scheduler->max_user_leftover        = max_user_leftover / 8;	/* convert to bytes */
            scheduler->max_common_leftover      = max_common_leftover / 8;	/* convert to bytes */
        
        /* register statistics */    
        ctp_module_register_stats(&scheduler->module, 
                                  (unsigned char *)&scheduler->stats, 
                                  sizeof(scheduler->stats));

        /* allocate the stats */
        ctp_module_allocate_per_user_stats(&scheduler->module, struct ctp_mod_scheduler_stats);

        /* allocate log */
        ctp_log_event_create("scheduler", 
                             sizeof(struct ctp_mod_scheduler_log_entry), 
                             500 * 32,
                             ctp_mod_scheduler_event_to_file,
                             &scheduler->log);
    }

    /* return the result */
    return result;
}

