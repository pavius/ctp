/* 
 * Module buffer pool
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
#include "common/buffer/bufpool/ctp_bufpool_prv.h"

/* init the buffer pool */
rv_t ctp_bufpool_create(const unsigned int max_data_length, 
                        const unsigned int initial_buffers,
                        void (*message_init_callback)(void *, ctp_buffer_t),
                        void *callback_arg,
                        handle_t *buf_pool)
{
    struct ctp_bufpool *buffer_pool;
    rv_t result;
    unsigned int buffer_idx;
    struct ctp_buffer_header *buffer;
    unsigned char *buffer_block, *current_buffer;

    /* allocate */
    buffer_pool = malloc(sizeof(struct ctp_bufpool));

    /* check if allocated */
    if (buffer_pool == NULL)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_alloc_buf_pool;
    }

    /* init queue */
    ctp_bufq_create(&buffer_pool->q);

    /* allocate one big block to save OS per-heap-block overhead */
    buffer_block = malloc(max_data_length * initial_buffers);

    /* check if allocated */
    if (buffer_block == NULL)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_alloc_msg;
    }

    /* add buffers to pool */
    for (buffer_idx = 0, current_buffer = buffer_block; 
         buffer_idx < initial_buffers; 
         ++buffer_idx, current_buffer += max_data_length)
    {
        /* point to beginning of block and initialize a buffer header there */
        buffer = (struct ctp_buffer_header *)current_buffer;

        /* for debugging */
        memset(buffer, 0xFF, max_data_length);

        /* set pool */
        buffer->q = buffer_pool->q;

        /* if there's an init function, call it */
        if (message_init_callback) message_init_callback(callback_arg, buffer);

        /* add to queue */
        ctp_bufq_push_tail(buffer_pool->q, buffer);
    }

    /* set result */
    *buf_pool = (buffer_pool);

    /* ok */
    return RV_OK;

err_alloc_msg:
    free(buffer_pool);
err_alloc_buf_pool:
    return result;    
}

/* allocate buffer */
ctp_buffer_t ctp_bufpool_alloc_buf(handle_t buf_pool)
{
    struct ctp_bufpool *buffer_pool;
    struct ctp_buffer_header *buffer;

    /* initialize locals */
    buffer_pool = (struct ctp_bufpool *)buf_pool;
    buffer = NULL;

    /* lock */
    ctp_bufq_lock(buffer_pool->q);

    /* get the buffer */
    buffer = (struct ctp_buffer_header *)ctp_bufq_pull_head(buffer_pool->q);

    /* unlock */
    ctp_bufq_unlock(buffer_pool->q);

    /* return buffer */
    return buffer;
}

/* free buffer */
void ctp_bufpool_free_buf(ctp_buffer_t buffer)
{
    struct ctp_buffer_header *buf_header = (struct ctp_buffer_header *)buffer;

    /* lock */
    ctp_bufq_lock(buf_header->q);

    /* get the buffer */
    ctp_bufq_push_tail(buf_header->q, buffer);

    /* unlock */
    ctp_bufq_unlock(buf_header->q);
}

/* test buffer pool */
void ctp_bufpool_test()
{
#if 0
    handle_t buf_pool;
    rv_t result;
    struct ctp_buffer_header *buffers[1024];

    result = ctp_bufpool_create(1550, 256, &buf_pool);
    /* assert(result == CTP_OK); */

    /* seed rng */
    srand(time(NULL));

    /* forever */
    while (1)
    {
        unsigned int buffers_to_alloc = (rand() % 200) + 1;
        unsigned int buffer_idx;

        /* log */
        printf("Allocating %d buffers\n", buffers_to_alloc);

        /* allocate buffers */
        for (buffer_idx = 0; buffer_idx < buffers_to_alloc; ++buffer_idx)
        {
            buffers[buffer_idx] = ctp_bufpool_alloc_buf(buf_pool);
        }

        /* log */
        printf("Freeing %d buffers\n", buffers_to_alloc);

        /* allocate buffers */
        for (buffer_idx = 0; buffer_idx < buffers_to_alloc; ++buffer_idx)
        {
            ctp_bufpool_free_buf(buffers[buffer_idx]);
        }

    }
#endif
}
