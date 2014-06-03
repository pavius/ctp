/* 
 * NodeB configuration module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: October 9th, 2011
 *
 */

#include "config/ctp_config_nodeb.h"
#include "config/ctp_config_tunnel.h"
#include "config/ctp_config_user.h"

/* init nodeb */                                                               
void ctp_config_nodeb_init(struct ctp_config_nodeb *nodeb)
{
    /* initialize the tunnel list */
    TAILQ_INIT(&nodeb->tunnel_list);

    /* start as unlocked. we will only become locked when the scheduler sends data from
     * user queues within this nodeb
     */
    nodeb->scheduling_state = CTP_CONFIG_NODEB_SCHED_STATE_UNLOCKED;

    /* initialize the two user actual queue lists */
    SIMPLEQ_INIT(&nodeb->user_queues[0].userq_list);
    SIMPLEQ_INIT(&nodeb->user_queues[1].userq_list);
    nodeb->user_queues[0].count = 0;
    nodeb->user_queues[1].count = 0;

    /* point arbitrarily. during runtime, this will swap back and forth */
    nodeb->current_tti_active_user_qs = &nodeb->user_queues[0];
    nodeb->next_tti_active_user_qs = &nodeb->user_queues[1];

    /* zero out common credits */
    nodeb->common_leftover_credits = 0;

    /* initialize the lock */
    pthread_spin_init(&nodeb->lock, 0);
}

/* post init nodeb */                                                               
void ctp_config_nodeb_post_config_init(struct ctp_config_nodeb *nodeb)
{
    /* calculate bits per tti (= bits per second * (tti in ms) / 1000)
     * then divide by 8 to receive bytes per tti
     */
    nodeb->max_bandwidth_bp_tti = (nodeb->max_bandwidth_bps * 10 / 1000.0) / 8;
}

/* add a tunnel */
void ctp_config_nodeb_add_tunnel(struct ctp_config_nodeb *nodeb, struct ctp_config_tunnel *tunnel)
{
    /* shove to tunnel list */
    TAILQ_INSERT_TAIL(&nodeb->tunnel_list, tunnel, nodeb_entry);
}
    
/* lock nodeb for scheduling */
void ctp_config_nodeb_lock_for_scheduling(struct ctp_config_nodeb *nodeb,
                                          struct timespec *current_time)
{
    struct timespec now, diff;

    /* get current time */
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    /* populate max schedule interval for node b before doing anything */
    timespec_diff(&nodeb->last_schedule_time,
                  &now,
                  &diff);

    /* nodeb->max_schedule_interval is 0 on the first call to this function */
    if (nodeb->max_schedule_interval != 0)
    {
        /* populate histogram */
        if (diff.tv_nsec < 9000000)          nodeb->schedule_interval_histogram[0]++;
        else if (diff.tv_nsec < 11000000)    nodeb->schedule_interval_histogram[1]++;
        else if (diff.tv_nsec < 15000000)    nodeb->schedule_interval_histogram[2]++;
        else if (diff.tv_nsec < 20000000)    nodeb->schedule_interval_histogram[3]++;
        else                                 nodeb->schedule_interval_histogram[4]++;

        /* do we have a new record? */
        if (diff.tv_nsec > nodeb->max_schedule_interval)
        {
            /* set the record for longest interval */
            nodeb->max_schedule_interval = diff.tv_nsec;
        }
    }
    else
    {
        /* set it to something so next call will actually calculate */
        nodeb->max_schedule_interval = 1;
    }

    /* save current sched-time */
    nodeb->last_schedule_time = now;    

    /* lock */
    pthread_spin_lock(&nodeb->lock);

    /* set state */
    nodeb->scheduling_state = CTP_CONFIG_NODEB_SCHED_STATE_LOCKED;

    /* unlock */
    pthread_spin_unlock(&nodeb->lock);

    /* return time */
    *current_time = now;
}

/* swap two queue pointers */
void ctp_config_nodeb_swap_user_q_ptrs(struct ctp_config_nodeb_user_qs **first,
                                       struct ctp_config_nodeb_user_qs **second)
{
    /* save first to temp */
    struct ctp_config_nodeb_user_qs *temp = *first;

    /* shove second to first */
    *first = *second;

    /* shove temporary (first) to second*/
    *second = temp;
}

/* unlock nodeb for scheduling */
void ctp_config_nodeb_unlock_for_scheduling(struct ctp_config_nodeb *nodeb)
{
    /* lock */
    pthread_spin_lock(&nodeb->lock);

    /* set state */
    nodeb->scheduling_state = CTP_CONFIG_NODEB_SCHED_STATE_UNLOCKED;

    /* empty out the current tti queue, seeing how it has just been handled */
    SIMPLEQ_INIT(&nodeb->current_tti_active_user_qs->userq_list);
    nodeb->current_tti_active_user_qs->count = 0;

    /* swap pointers. essentially all user queues which were scheduled for next tti
     * are now scheduled for the current tti
     */
    ctp_config_nodeb_swap_user_q_ptrs(&nodeb->current_tti_active_user_qs, 
                                      &nodeb->next_tti_active_user_qs);

    /* unlock */
    pthread_spin_unlock(&nodeb->lock);
}

/* pop a user from a user queue */
struct ctp_config_user *ctp_config_nodeb_pop_active_user(struct ctp_config_nodeb *nodeb, 
                                                         struct ctp_config_nodeb_user_qs *source_q)
{
    struct ctp_config_user *user = NULL;

    /* lock */
    pthread_spin_lock(&nodeb->lock);

    /* check if queue has an entry */
    if (!SIMPLEQ_EMPTY(&source_q->userq_list))
    {
        /* get first */
        user = SIMPLEQ_FIRST(&source_q->userq_list);

        /* remove the user */
        SIMPLEQ_REMOVE_HEAD(&source_q->userq_list, pdu_q_active_entry);

        /* decrement user count */
        source_q->count--;
    }

    /* unlock */
    pthread_spin_unlock(&nodeb->lock);

    /* return the user */ 
    return user;
}

/* add a user queue to the list of active users. if the scheduling is unlocked (meaning the scheduler
 * is not currently handling this nodeb, the user will be added to current_tti_active_user_qs. If it
 * is, it will be added to next_tti_active_user_qs.
 */
void ctp_config_nodeb_add_active_user_q(struct ctp_config_nodeb *nodeb, 
                                        struct ctp_config_user *user)
{
    struct ctp_config_nodeb_user_qs *target_q_list;

    /* lock */
    pthread_spin_lock(&nodeb->lock);

    /* are we locked for scheduling? */
    if (nodeb->scheduling_state == CTP_CONFIG_NODEB_SCHED_STATE_UNLOCKED)
    {
        /* no scheduling is being performed on this nodeb at the moment. shove the queue into
         * the current tti (to be scheduled next time)
         */
        target_q_list = nodeb->current_tti_active_user_qs;
    }
    else
    {
        /* the nodeb is currently being scheduled so we must push this queue to the next tti */
        target_q_list = nodeb->next_tti_active_user_qs;
    }

    /* shove to target queue */
    SIMPLEQ_INSERT_TAIL(&target_q_list->userq_list, user, pdu_q_active_entry);

    /* increment number of entities int he list */
    target_q_list->count++;

    /* unlock */
    pthread_spin_unlock(&nodeb->lock);
}

