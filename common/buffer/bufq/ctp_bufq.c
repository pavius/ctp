/* 
 * Module buffer q
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include "common/buffer/bufq/ctp_bufq_prv.h"

/* init the buffer q */
rv_t ctp_bufq_create(handle_t *buf_q)
{
    struct ctp_bufq *buffer_q;
    rv_t result;
    struct ctp_buffer_header *buffer;

    /* allocate */
    buffer_q = malloc(sizeof(struct ctp_bufq));

    /* check if allocated */
    if (buffer_q == NULL)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_alloc_buf_q;
    }

    /* init queue */
    SIMPLEQ_INIT(&buffer_q->buf_q);

    /* init lock */
    pthread_spin_init(&buffer_q->lock, 0);

    /* inti counter */
    buffer_q->queued_buffers = 0;

    /* set result */
    *buf_q = (buffer_q);

    /* ok */
    return RV_OK;

err_alloc_buf_q:
    return result;    
}

/* push a buffer onto the tail of the queue */
void ctp_bufq_push_tail(handle_t buf_q, ctp_buffer_t buffer)
{
    struct ctp_buffer_header *buf_header = (struct ctp_buffer_header *)buffer;
    struct ctp_bufq *buffer_q = (struct ctp_bufq *)buf_q;

    /* post to tail of queue */
    SIMPLEQ_INSERT_TAIL(&buffer_q->buf_q, buf_header, q_entry);

    /* inccrement buffer count */
    buffer_q->queued_buffers++;
}

/* pull a buffer from the head of the queue */
ctp_buffer_t ctp_bufq_pull_head(handle_t buf_q)
{
    struct ctp_bufq *buffer_q;
    struct ctp_buffer_header *buffer;

    /* initialize locals */
    buffer_q = (struct ctp_bufq *)buf_q;
    buffer = NULL;

    /* check if queue has an entry */
    if (!SIMPLEQ_EMPTY(&buffer_q->buf_q))
    {
        /* get first */
        buffer = SIMPLEQ_FIRST(&buffer_q->buf_q);

        /* remove the buffer and handle it */
        SIMPLEQ_REMOVE_HEAD(&buffer_q->buf_q, q_entry);

        /* decrement buffer count */
        buffer_q->queued_buffers--;
    }

    /* return buffer */
    return buffer;
}

/* lock (busy wait) */
void ctp_bufq_lock(handle_t buf_q)
{
    struct ctp_bufq *buffer_q = (struct ctp_bufq *)buf_q;;

    /* lock */
    pthread_spin_lock(&buffer_q->lock);
}

/* unlock (busy wait) */
void ctp_bufq_unlock(handle_t buf_q)
{
    struct ctp_bufq *buffer_q = (struct ctp_bufq *)buf_q;;

    /* unlock */
    pthread_spin_unlock(&buffer_q->lock);
}

/* pending messages */
unsigned int ctp_bufq_buffer_count(handle_t buf_q)
{
    struct ctp_bufq *buffer_q = (struct ctp_bufq *)buf_q;;

    /* return # of buffers */
    return buffer_q->queued_buffers;
}

