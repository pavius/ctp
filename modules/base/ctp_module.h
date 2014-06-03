/* 
 * Base object module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MODULE_H_
#define __CTP_MODULE_H_

#include <stdbool.h>
#include "common/utils/common.h"
#include "common/utils/data_struct.h"
#include "common/buffer/bufpool/ctp_bufpool.h"

/* max name size */
#define CTP_MODULE_MAX_NAME_SZ (64)

/* max number of created modules */
#define CTP_MODULE_MAX_MODULES (64)

/* 
 * Module Message
 */

/* forward declare */
struct ctp_module;
struct ctp_config_user;

/* flags */
#define CTP_MODULE_MESSAGE_FLAG_CONTROL     (1 << 0)    /* message is a control message */

/* an ctp module message header */
struct ctp_module_message_header
{
    struct ctp_buffer_header                bufpool_header;           /* to be able to allocate from a pool */  
    SIMPLEQ_ENTRY(ctp_module_message)       q_entry;                  /* to support shoving in a queue      */
    struct ctp_module                       *module;
    struct ctp_config_user                  *user;
    unsigned char                           *write_head;
    unsigned char                           *write_tail;
    unsigned char                           *head_of_written_data;    /* explictly controlled by code */
    unsigned char                           *tail_of_written_data;    /* explictly controlled by code */
    unsigned char                           *absolute_buffer_start;
    unsigned char                           *absolute_buffer_end;
    unsigned char                           pdu_count;
    unsigned int                            flags;
};

/* an ctp module message */
struct ctp_module_message
{
    /* header */
	struct ctp_module_message_header header;

    /* variable number of bytes */
    unsigned char data[1];
};

/* get message size */
#define ctp_module_msg_size(payload_size) (sizeof(struct ctp_module_message_header) + payload_size)

/* define a queue of messages */
SIMPLEQ_HEAD(ctp_module_msgq, ctp_module_message) ctp_module_msgq;

/* initialize a message */
rv_t ctp_module_msg_init(struct ctp_module_message *message, 
                         const unsigned int max_data_size);

/* set header space for a message */
rv_t ctp_module_msg_set_header_space(struct ctp_module_message *message,
                                     const unsigned int header_space);

/* write a single byte to the end of the written part */
rv_t ctp_module_msg_write_tail_byte(struct ctp_module_message *message, const unsigned char data);

/* write a buffer to the end of the written part */
rv_t ctp_module_msg_write_tail_buffer(struct ctp_module_message *message, 
                                      const unsigned char *buffer,
                                      const unsigned int size);

/* write a single byte at the beginning of the written part */
rv_t ctp_module_msg_write_head_byte(struct ctp_module_message *message, const unsigned char data);

/* write a buffer to the beginning of the written part */
rv_t ctp_module_msg_write_head_buffer(struct ctp_module_message *message, 
                                      const unsigned char *buffer,
                                      const unsigned int size);

/* saves teh current tail/head as the point indicating where the first/last written byte in
 * the message are. this is to allow knowing exactly how much data was ever written in the message 
 * before head/tail seeks could have occured 
 */
#define ctp_module_msg_save_written_data_state(message)                                 \
    message->header.head_of_written_data = message->header.write_head;                  \
    message->header.tail_of_written_data = message->header.write_tail

/* seek @tail */
#define ctp_module_msg_seek_tail(message, size)                                         \
    do { message->header.write_tail += (size); } while (0)

/* seek @head */
#define ctp_module_msg_seek_head(message, size)                                         \
    do { message->header.write_head += (size); } while (0)

/* get number of bytes left @ tail */
#define ctp_module_msg_tail_room_left(message)                                          \
    (unsigned int)(message->header.absolute_buffer_end - message->header.write_tail)

/* get number of bytes left @ head */
#define ctp_module_msg_head_room_left(message)                                          \
    (unsigned int)(message->header.write_head - message->header.absolute_buffer_start)

/* get message written size */
#define ctp_module_msg_get_bytes_written(message)                                       \
    (unsigned int)(message->header.write_tail - message->header.write_head)

/* get tail */
#define ctp_module_msg_get_tail(message) message->header.write_tail
    
/* get head */
#define ctp_module_msg_get_head(message) message->header.write_head

/* reset write state */
void ctp_module_msg_reset_write_state(struct ctp_module_message *message, 
                                      const unsigned int header_space);

/* 
 * Module
 */

/* a module id */
typedef unsigned int module_id_t;

/* types of module - update CTP_MODULE_TYPE_NAMES accordingly */
enum ctp_module_type
{
    CTP_MODTYPE_BASE_THREAD,
    CTP_MODTYPE_BASE_QUEUE,
    CTP_MODTYPE_ETH_RX,
    CTP_MODTYPE_ETH_TX,
    CTP_MODTYPE_CLASSIFIER,
    CTP_MODTYPE_RLC_SEG,
    CTP_MODTYPE_RLC_RAS,
    CTP_MODTYPE_IUB_ENCAP,
    CTP_MODTYPE_IUB_DECAP,
    CTP_MODTYPE_UTIL_ANALYZER,
    CTP_MODTYPE_SCHEDULER,
    CTP_MODTYPE_GENERATOR,
    CTP_MODTYPE_SCC
};

/* generic module */
struct ctp_module
{
    /* callbacks */
    void (*poll)(struct ctp_module *);
    void (*recv_message)(struct ctp_module *, struct ctp_module_message *);
    void (*process_message)(struct ctp_module *, struct ctp_module_message *);
    void (*on_before_encode_stats)(struct ctp_module *);

    /* members */
    module_id_t             id;            
    enum ctp_module_type    type;
    char                    name[CTP_MODULE_MAX_NAME_SZ];
    struct ctp_module       *input;
    struct ctp_module       *output;
    struct ctp_module       *thread;
    unsigned char           *stats;
    unsigned int            stats_length;
    bool                    stats_per_user;
};

/* per statistics header */
struct ctp_module_stat_header
{
    module_id_t              id; 
    enum ctp_module_type     type;
    unsigned int             size;

} __attribute((packed));

/* create a module */
rv_t ctp_module_create(const unsigned int module_desc_size,
                       const enum ctp_module_type type, 
                       const char *name, handle_t *handle);

/* get module type name */
const char* ctp_module_get_type_name(const enum ctp_module_type type);

/* set the output of the module */
rv_t ctp_module_set_output(handle_t module, handle_t output_module);

/* forward the message to the output */
rv_t ctp_module_forward_message(handle_t module, struct ctp_module_message *message);

/* set a module's process message routine */
rv_t ctp_module_set_process_message(handle_t module, 
                                    void (*process_message)(struct ctp_module *, 
                                                            struct ctp_module_message *));

/* register statistics structure */
void ctp_module_register_stats(handle_t module, 
                               unsigned char *stats_structure,
                               const unsigned char stats_struct_length);

/* allocate per user statistics */
#define ctp_module_allocate_per_user_stats(module, stats_structure)                                 \
        (module)->stats_length = (sizeof(stats_structure) * ctp_config_get_active_users_count());   \
        (module)->stats = malloc((module)->stats_length);                                           \
        ctp_assert((module)->stats != NULL, "Failed to allocate user statistics");                  \
        bzero((module)->stats, (module)->stats_length);                                             \
        (module)->stats_per_user = true;
    

/* encode statistics into a message */
rv_t ctp_module_encode_statistics(handle_t module, 
                                  struct ctp_module_message *message);

/* reset statistics */
rv_t ctp_module_reset_statistics(handle_t module);

/* get number of created modules */
unsigned int ctp_module_get_module_count();

/* get a module by id */
handle_t ctp_module_get_module_by_id(const module_id_t id);

#endif /* __CTP_MODULE_H_ */
