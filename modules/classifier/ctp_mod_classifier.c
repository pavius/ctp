/* 
 * Ethernet transmitter module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include "modules/classifier/ctp_mod_classifier_prv.h"
#include "config/ctp_config.h"
#include "common/utils/assert.h"

/* matches all the patterns of a classifier to a frame and returns whether the frame
 *  successfully passed all matches
 */
bool ctp_mod_classifier_match_patterns(struct ctp_mod_classifier *module, 
                                       struct ctp_module_message *message)
{
    bool message_match = true, pattern_match;
    unsigned int pattern_idx;
    const struct ctp_mod_classifier_pattern *pattern = module->patterns;
    unsigned char *message_data;

    /* get the start of data */
    message_data = ctp_module_msg_get_head(message);

    /* iterate through patterns */
    for (pattern_idx = 0; 
         pattern_idx < module->pattern_count && message_match; 
         ++pattern_idx, ++pattern)
    {
        /* TODO: check overflow */

        /* do the compare */
        pattern_match = memcmp(&message_data[pattern->offset],
                               &pattern->data,
                               pattern->size) == 0;

        /* message matches the pattern if mode is to match and there is a match, or mode is not to
         * match and pattern doesn't match
         */
        message_match = (((pattern->mode == CTP_MOD_CLASSIFIER_PM_MUST_MATCH) && pattern_match) ||
                         ((pattern->mode == CTP_MOD_CLASSIFIER_PM_MUST_NOT_MATCH) && !pattern_match));
    }

    /* return whether there is a match */
    return message_match;
}

/* process a message */
void ctp_mod_classifier_process_message(struct ctp_module *module, 
                                        struct ctp_module_message *message)
{
    struct ethhdr *eth_header;
    struct ctp_mod_classifier *classifier = (struct ctp_mod_classifier *)module;
    user_id_t user_id;
    struct ctp_config_user *user;
    struct ctp_module *handler;
    bool searchable_frame;

    /* by default user is null, indicating no such user has been found */
    user = NULL;

    /* get the ethernet header */
    eth_header = (struct ethhdr *)ctp_module_msg_get_head(message);

    /* get whether the frame adheres to the pattern rules */
    searchable_frame = ctp_mod_classifier_match_patterns(classifier, message);
    
    /* if this frame is searchable, try to look for the user */
    if (searchable_frame)
    {
        /* according to search point */
        if (classifier->user_id_search_point == CTP_MOD_CLASSIFIER_SP_HEAD)
        {
            /* get the user id from head + offset */
            user_id = *(user_id_t *)(ctp_module_msg_get_head(message) + classifier->user_id_offset);
        }
        else
        {
            /* get the user id from tail - offset */
            user_id = *(user_id_t *)(ctp_module_msg_get_tail(message) - classifier->user_id_offset);
        }
    
        /* to host order */
        user_id = ntohs(user_id);
    
        /* get the user */
        user = ctp_config_get_user_by_id(user_id);
    }

    /* is a user mapped to this stream? */
    if (user && user->active)
    {
        /* set the user pointer in the packet, to be used by the next modules */
        message->header.user = user;

        /* get the hadnler by classifier id */
        handler = message->header.user->handlers[classifier->id];

        /* stats */
        classifier->stats.classified_frames++;
    }
    else
    {
        /* the handler is the module registered to be in the unclassified output */
        handler = classifier->unclassified_output;

        /* stats */
        classifier->stats.unclassified_frames++;
    }

    /* handle in user handler */
    ctp_assert(handler != NULL, "User has no mapped handler");

    /* handle in handler */
    handler->recv_message(handler, message);
}

/* set the unclassified output */
rv_t ctp_mod_classifier_set_unclassified_output(handle_t module, 
                                                handle_t unclassified_output)
{
    struct ctp_mod_classifier *classifier = (struct ctp_mod_classifier *)module;

    /* set the output */
    classifier->unclassified_output = (struct ctp_module *)unclassified_output;

    /* success */
    return RV_OK;
}

/* create an ethernet entity */
rv_t ctp_mod_classifier_create(const char *name, 
                               const enum ctp_mod_classifier_search_point user_id_search_point, 
                               const unsigned int user_id_offset, 
                               const struct ctp_mod_classifier_pattern *patterns, 
                               const unsigned int pattern_count,
                               handle_t *module)
{
    rv_t result;
    struct ctp_mod_classifier *classifier;

    /* incrementing classifier id - good enough until delete is required */
    static unsigned char classifier_id = 0;

    /* make sure offset is aligned */
    ctp_assert((user_id_offset & 0x1) == 0, "Offset must be aligned");

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_classifier), 
                               CTP_MODTYPE_CLASSIFIER, name, module);

    /* call base */
    if (result == RV_OK)
    {
        /* set classifier stuff */
        classifier = (struct ctp_mod_classifier *)(*module);
            ctp_module_set_process_message(classifier, ctp_mod_classifier_process_message);
            classifier->user_id_offset          = user_id_offset;
            classifier->id                      = classifier_id++;
            classifier->user_id_search_point    = user_id_search_point;
        
        /* make sure pattern count is sane */        
        ctp_assert(pattern_count < array_size(classifier->patterns), "Too many classifier patterns");

        /* copy patterns */    
        classifier->pattern_count = pattern_count;
        if (pattern_count) 
        {
            /* do copy */
            memcpy(classifier->patterns, 
                   patterns, 
                   sizeof(struct ctp_mod_classifier_pattern) * pattern_count);
        }

        /* register statistics */    
        ctp_module_register_stats(&classifier->module, 
                                  (unsigned char *)&classifier->stats, 
                                  sizeof(classifier->stats));
    }

    /* return the result */
    return result;
}

/* bind a classifier to specific per-user output */
rv_t ctp_mod_classifier_bind_user_handler(handle_t classifier_handle, 
                                          struct ctp_config_user *user,
                                          handle_t handler)
{
    struct ctp_mod_classifier *classifier = (struct ctp_mod_classifier *)classifier_handle;

    /* make sure we won't overflow */
    ctp_assert(classifier->id < array_size(user->handlers), "Too many classifiers");

    /* register the handler at the position */
    user->handlers[classifier->id] = handler;

    /* success */
    return RV_OK;
}

