/* 
 * Module message queue
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include "modules/base/ctp_module_queue_prv.h"

/* pull a message */
bool ctp_module_queue_pull_message(struct ctp_module_queue *module)
{
    /* lock */
    pthread_spin_lock(&module->msgq_lock);

    /* check if queue has an entry */
    if (!SIMPLEQ_EMPTY(&module->msgq))
    {
        /* received message */
        struct ctp_module_message *message;

        /* get first */
        message = SIMPLEQ_FIRST(&module->msgq);

        /* remove the message and handle it */
        SIMPLEQ_REMOVE_HEAD(&module->msgq, header.q_entry);

        /* decrement # of messages in queue */
        --module->stats.msgq_message_count;

        /* unlock */
        pthread_spin_unlock(&module->msgq_lock);

        /* handle message in module that it was targeted at */
        message->header.module->process_message(message->header.module, message);

        /* message exists */
        return true;
    }
    else
    {
        /* unlock */
        pthread_spin_unlock(&module->msgq_lock);

        /* message doesn't exist */
        return false;
    }
}

/* poll messages */
void ctp_module_queue_poll(struct ctp_module *module)
{
    struct ctp_module_queue *this_module = (struct ctp_module_queue *)module;

    /* forever */
    while (1)
    {
        /* pull messages and handle them */
        ctp_module_queue_pull_message(this_module);
    }
}

/* receive the message by posting it to the queue */
void ctp_module_queue_recv_message(struct ctp_module *module,
                                   struct ctp_module_message *message)
{
    struct ctp_module *attached_module  = module;
    struct ctp_module_queue *queue      = (struct ctp_module_queue *)attached_module->input;
    
    /* save target module in message */
    message->header.module = attached_module;

    /* lock */
    pthread_spin_lock(&queue->msgq_lock);

    /* post to tail of queue */
    SIMPLEQ_INSERT_TAIL(&queue->msgq, message, header.q_entry);

    /* increment # of messages in queue and check if high watermark passed */
    if (++queue->stats.msgq_message_count > queue->stats.msgq_high_watermark)
        queue->stats.msgq_high_watermark = queue->stats.msgq_message_count;

    /* unlock */
    pthread_spin_unlock(&queue->msgq_lock);
}

/* attach the queue to a module */
rv_t ctp_module_queue_attach_module(handle_t queue, handle_t module)
{
    struct ctp_module_queue *this_module;
    struct ctp_module *attached_module;

    /* get structures */
    this_module     = (struct ctp_module_queue *)queue;
    attached_module = (struct ctp_module *)module;

    /* replace module's recv message with that of the queue's message */
    attached_module->recv_message = this_module->module.recv_message;

    /* set as input into the module */
    attached_module->input = (struct ctp_module *)this_module;

    /* if this module has a poll() interface, use it instead of ours */
    if (attached_module->poll != NULL)
    {
        /* override our poll with that of module */
        this_module->module.poll = attached_module->poll;
    }

    /* copy attached module name */
    safe_strncpy(this_module->module.name, 
                 attached_module->name, 
                 sizeof(this_module->module.name));

    /* success */
    return RV_OK;
}

/* create a module queue */
rv_t ctp_module_queue_create(handle_t *module)
{
    struct ctp_module_queue *queue_module;
    rv_t result;

    /* call base */
    result = ctp_module_create(sizeof(struct ctp_module_queue), 
                               CTP_MODTYPE_BASE_QUEUE, 
                               "queue", module);

    /* get queue */
    queue_module = (struct ctp_module_queue *)(*module);

    /* check if succeeded */
    if (result == RV_OK)
    {
        /* initialize queue */
        SIMPLEQ_INIT(&queue_module->msgq);

        /* init queue lock */
        pthread_spin_init(&queue_module->msgq_lock, 0);

        /* set callbacks */
        queue_module->module.recv_message   = ctp_module_queue_recv_message;
        queue_module->module.poll           = ctp_module_queue_poll;


        /* register statistics */    
        ctp_module_register_stats(&queue_module->module, 
                                  (unsigned char *)&queue_module->stats, 
                                  sizeof(queue_module->stats));

        /* success */
        return RV_OK;
    }
    else 
    {
        /* return error */
        return result;
    }
}

