/* 
 * Module message pool
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common/utils/data_struct.h"
#include "modules/base/ctp_module_msgpool_prv.h"

/* initialize a message */
void ctp_module_msgpool_message_init_callback(void *max_data_length, ctp_buffer_t buffer)
{
    /* get message */
    struct ctp_module_message *message = (struct ctp_module_message *)buffer;

    /* init the message */
    ctp_module_msg_init(message, (unsigned int)max_data_length);
}

/* init the message pool */
rv_t ctp_module_msgpool_create(const unsigned int max_data_length, 
                               const unsigned int initial_messages,
                               handle_t *msg_pool)
{
    rv_t result;

    /* total length (data + header) */
    unsigned int total_message_length = sizeof(struct ctp_module_message_header) + max_data_length;

    /* create a buffer pool of equivalent value, for each message call init */
    result = ctp_bufpool_create(total_message_length, initial_messages, 
                                ctp_module_msgpool_message_init_callback, (void *)max_data_length,
                                msg_pool);

    /* ok */
    return result;
}

/* allocate message */
struct ctp_module_message* ctp_module_msgpool_alloc_msg(handle_t msg_pool)
{
    /* just allocate and cast */
    return (struct ctp_module_message *)ctp_bufpool_alloc_buf(msg_pool);
}

/* free message */
void ctp_module_msgpool_free_msg(struct ctp_module_message *message)
{
    /* just free */
    ctp_bufpool_free_buf((ctp_buffer_t)message);
}

