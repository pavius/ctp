/* 
 * Base object module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdlib.h>
#include <string.h>
#include "common/utils/common.h"
#include "common/utils/assert.h"
#include "modules/base/ctp_module_prv.h"
#include "modules/base/ctp_module_msgpool_prv.h"

/* initialize a message */
rv_t ctp_module_msg_init(struct ctp_module_message *message, 
                         const unsigned int max_data_size)
{
    /* set buffer start/end */
    message->header.absolute_buffer_start   = (unsigned char *)&message->data;
    message->header.absolute_buffer_end     = (unsigned char *)(&message->data + max_data_size);

    /* success */
    return RV_OK;
}

/* set header space for a message */
rv_t ctp_module_msg_set_header_space(struct ctp_module_message *message,
                                     const unsigned int header_space)
{
    /* set write head/tail to location after expected headers */
    message->header.write_head = (unsigned char *)(message->data + header_space);
    message->header.write_tail = message->header.write_head;

    /* success */
    return RV_OK;
}

/* make sure */
#define ctp_module_msg_verify_tail_space(size)                                                  \
    ctp_assert((message->header.write_tail + size) <= message->header.absolute_buffer_end,      \
                "No more room left in buffer tail");

/* write a single byte to the end of the written part */
rv_t ctp_module_msg_write_tail_byte(struct ctp_module_message *message, const unsigned char data)
{
    /* make sure there's space */
    ctp_module_msg_verify_tail_space(sizeof(data));

    /* do the copy */
    *message->header.write_tail = data; 

    /* point to next byte */
    message->header.write_tail++;

    /* success */
    return RV_OK;
}

/* write a buffer to the end of the written part */
rv_t ctp_module_msg_write_tail_buffer(struct ctp_module_message *message, 
                                      const unsigned char *buffer,
                                      const unsigned int size)
{
    /* make sure there's space */
    ctp_module_msg_verify_tail_space(size);

    /* do the copy */
    memcpy(message->header.write_tail, buffer, size); 

    /* point to after written data */
    message->header.write_tail += size;

    /* success */
    return RV_OK;
}

/* make sure */
#define ctp_module_msg_verify_head_space(size)                                                  \
    ctp_assert((message->header.write_head - size) >= message->header.absolute_buffer_start,    \
                "No more room left in buffer head");

/* write a single byte at the beginning of the written part */
rv_t ctp_module_msg_write_head_byte(struct ctp_module_message *message, 
                                    const unsigned char data)
{
    /* make sure there's space */
    ctp_module_msg_verify_head_space(sizeof(data));

    /* point to previous byte */
    message->header.write_head--;

    /* do the copy */
    *message->header.write_head = data; 

    /* success */
    return RV_OK;
}

/* write a buffer to the beginning of the written part */
rv_t ctp_module_msg_write_head_buffer(struct ctp_module_message *message, 
                                      const unsigned char *buffer,
                                      const unsigned int size)
{
    /* make sure there's space */
    ctp_module_msg_verify_head_space(size);

    /* point to before written data */
    message->header.write_head -= size;

    /* do the copy */
    memcpy(message->header.write_head, buffer, size); 

    /* success */
    return RV_OK;
}

/* reset write state */
void ctp_module_msg_reset_write_state(struct ctp_module_message *message, 
                                      const unsigned int header_space)
{
    /* set write head to correct offset */
    message->header.write_head = message->header.absolute_buffer_start + header_space;

    /* set write tail to head */ 
    message->header.write_tail = message->header.write_head;

    /* reset flags */
    message->header.flags = 0;
}

/* create a module */
rv_t ctp_module_create(const unsigned int module_desc_size,
                       const enum ctp_module_type type, 
                       const char *name, handle_t *handle)
{
    rv_t result;
    struct ctp_module *module;

    /* create receiver */
    module = malloc(module_desc_size);

    /* check if allocated */
    if (module == NULL)
    {
        /* error */
        result = RV_ERR_ALLOC;
        goto err_mod_alloc;
    }

    /* initialize it */
    bzero(module, module_desc_size);

    /* copy name safely */
    safe_strncpy(module->name, name, sizeof(module->name));

    /* set the type */
    module->type = type;

    /* set the id TODO: support delete */
    module->id = ctp_module_next_free_id++;

    /* set the handle */
    *handle = (handle_t)module;

    /* register the module @ id */
    ctp_assert(array_size(ctp_created_modules) > module->id, "Too many modules");
    ctp_created_modules[module->id] = module;

    /* increment number of modules */
    ctp_module_count++;

    /* ok */
    return RV_OK;

err_mod_alloc:
    return result;       
}

/* set the output of the module */
rv_t ctp_module_set_output(handle_t module, handle_t output_module)
{
    struct ctp_module *this_module = (struct ctp_module *)module;

    /* set it */
    this_module->output = output_module;

    /* success */
    return RV_OK;
}

/* forward the message to the output */
rv_t ctp_module_forward_message(handle_t module, struct ctp_module_message *message)
{
    struct ctp_module *this_module = (struct ctp_module *)module;

    /* output must support recv message */
    ctp_assert(this_module->output->recv_message != NULL, "Module has no registered forwarding module");

    /* forward the message to the output */
    this_module->output->recv_message(this_module->output, message);

    /* success */
    return RV_OK;
}

/* set a module's process message routine */
rv_t ctp_module_set_process_message(handle_t module, 
                                    void (*process_message)(struct ctp_module *, 
                                                            struct ctp_module_message *))
{
    struct ctp_module *this_module = (struct ctp_module *)module;

    /* set both process and recv message */
    this_module->process_message = process_message;
    this_module->recv_message    = process_message;

    /* success */
    return RV_OK;
}

/* encode statistics into a message */
rv_t ctp_module_encode_statistics(handle_t module, 
                                  struct ctp_module_message *message)
{
    struct ctp_module *the_module = (struct ctp_module *)module;
    struct ctp_module_stat_header header;

    /* if there is a registered stat struture - space is verified on write */
    if (the_module->stats != NULL)
    {
        /* initialize the header */
        header.id   = the_module->id;
        header.type = the_module->type;
        header.size = the_module->stats_length;

        /* some modules need to prepare stuff */
        if (the_module->on_before_encode_stats) 
            the_module->on_before_encode_stats(the_module);

        /* write the header */
        ctp_module_msg_write_tail_buffer(message, 
                                         (const unsigned char *)&header, 
                                         sizeof(header));

        /* write the stats */
        ctp_module_msg_write_tail_buffer(message, 
                                         (const unsigned char *)the_module->stats,
                                         the_module->stats_length);
    }

    /* success */
    return RV_OK;
}

/* reset statistics */
rv_t ctp_module_reset_statistics(handle_t module)
{
    struct ctp_module *the_module = (struct ctp_module *)module;

    /* if there is a registered stat struture */
    if (the_module->stats != NULL)
    {
        /* zero it out */
        bzero(the_module->stats, the_module->stats_length);
    }

    /* done */
    return RV_OK;
}

/* get number of created modules */
unsigned int ctp_module_get_module_count()
{
    /* return the counter */
    return ctp_module_count;
}

/* get a module by id */
handle_t ctp_module_get_module_by_id(const module_id_t id)
{
    /* check that id is valid */
    ctp_assert(array_size(ctp_created_modules) > id, "Invalid module index");

    /* return teh module */
    return (handle_t)ctp_created_modules[id];
}

/* get module type name */
const char* ctp_module_get_type_name(const enum ctp_module_type type)
{
    /* make sure its valid */
    ctp_assert((unsigned int)type < array_size(CTP_MODULE_TYPE_NAMES), "Invalid type");

    /* return the string */
    return CTP_MODULE_TYPE_NAMES[type];
}

/* register statistics structure */
void ctp_module_register_stats(handle_t module, 
                               unsigned char *stats_structure,
                               const unsigned char stats_struct_length)
{
    struct ctp_module *the_module = (struct ctp_module *)module;

    /* save stats structure and length */
    the_module->stats = (unsigned char *)stats_structure;
    the_module->stats_length = stats_struct_length;
}


