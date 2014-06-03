/* 
 * Generator utility 
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include "modules/generator/ctp_mod_generator_prv.h"
#include "common/utils/assert.h"

/* register a flow on a generator */
void ctp_mod_generator_register_flow(handle_t module, handle_t flow)
{
    /* get the receiver from module */
    struct ctp_mod_generator *generator = ((struct ctp_mod_generator *)module);

    /* make sure there's an empty slot for the flow */
    ctp_assert(array_size(generator->flows) > (generator->flow_count + 1), 
               "Max number of generator flows reached");

    /* register the flow */
    generator->flows[generator->flow_count++] = (struct ctp_mod_generator_flow *)flow;
}

/* transmit a frame on a flow */
void ctp_mod_generator_transmit(struct ctp_mod_generator *generator,
                                struct ctp_mod_generator_flow *flow)
{
    struct ctp_module_message *sdu_message;
    unsigned int payload_size, payload_byte_idx;

    /* allocate a buffer */
    sdu_message = (struct ctp_module_message *)ctp_module_msgpool_alloc_msg(flow->generator->sdu_pool);
    ctp_assert(sdu_message != NULL, "SDU messages depleted");
    
    /* set user */
    sdu_message->header.user = flow->user;

    /* initialize the message - no headers will be prepended */
    ctp_module_msg_reset_write_state(sdu_message, flow->total_header_size);

    /* make sure header + trailer doesn't leaves room for payload */
    ctp_assert(flow->next_tx_size > (flow->total_header_size + flow->trailer_size),
               "Can't generate packet. Too small"); 

    /* how much payload do we need to generate? */
    payload_size = (flow->next_tx_size - (flow->total_header_size + flow->trailer_size));

    /* populate payload */
    for (payload_byte_idx = 0; 
          payload_byte_idx < payload_size; 
          ++payload_byte_idx)
    {
        /* write the byte */
        ctp_module_msg_write_tail_byte(sdu_message, payload_byte_idx & 0xFF);
    }

    /* write the header */
    ctp_module_msg_write_head_buffer(sdu_message, flow->header, flow->header_size);

    /* do any post processing like modify headers/add trailer and such */
    if (flow->on_before_tx) flow->on_before_tx(flow, sdu_message);

    /* forward the message */
    ctp_module_forward_message(generator, sdu_message);

    /* increment for next time */
    flow->next_tx_size++;

    /* check overflow */
    if (flow->next_tx_size > flow->max_size) flow->next_tx_size = flow->min_size;
}

/* generator thread function */
void ctp_mod_generator_poll(struct ctp_module *module)
{
    unsigned int flow_index;
    struct timespec now;

    /* get the receiver from module */
    struct ctp_mod_generator *generator = ((struct ctp_mod_generator *)module);

    /* iterate over flows */
    for (flow_index = 0; flow_index < generator->flow_count; ++flow_index)
    {
        /* get the flow */
        struct ctp_mod_generator_flow *flow = generator->flows[flow_index];

        /* get current time */
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* check if passed deadline of flow */
        if (timespec_compare(&now, &flow->next_tx_time) > 0)
        {
            /* do the transmit */
            ctp_mod_generator_transmit(generator, flow);

            /* set next time */
            timespec_add_ns(&now, flow->ifg, &flow->next_tx_time);
        }
    }
}

/* create an ethernet entity */
rv_t ctp_mod_generator_create(handle_t *module, 
                              const char *name, 
                              handle_t sdu_pool)
{
    rv_t result;
    struct ctp_mod_generator *generator;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_generator), 
                               CTP_MODTYPE_GENERATOR, name, module);

    /* call base */
    if (result == RV_OK)
    {
        /* set generator stuff */
        generator = (struct ctp_mod_generator *)(*module);
            generator->module.poll = ctp_mod_generator_poll;
            generator->sdu_pool    = sdu_pool;

        /* check the pool */
        if (result != RV_OK)
        {
            /* error */
            goto err_msg_pool_create;
        }
    }
    else
    {
        /* error */
        return result;
    }

err_msg_pool_create:
    return result;
}

