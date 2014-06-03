/* 
 * Ethernet classifier module
 * Void (c) 2011
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_CLASSIFIER_H_
#define __CTP_MOD_CLASSIFIER_H_

#include "common/utils/common.h"
#include "config/ctp_config_user.h"

/* statistics structure */
struct ctp_mod_classifier_stats
{
    unsigned long long      classified_frames;
    unsigned long long      unclassified_frames;

} __attribute((packed));

/* supported search point */
enum ctp_mod_classifier_search_point
{
    CTP_MOD_CLASSIFIER_SP_HEAD, 
    CTP_MOD_CLASSIFIER_SP_TAIL
};

/* pattern mode */
enum ctp_mod_classifier_pattern_mode
{
    CTP_MOD_CLASSIFIER_PM_MUST_MATCH, 
    CTP_MOD_CLASSIFIER_PM_MUST_NOT_MATCH
};

/* max pattern length in bytes */
#define CTP_MOD_CLASSIFIER_MAX_PATTERN_SIZE (16)

/* pattern structure */
struct ctp_mod_classifier_pattern
{
    unsigned int                            offset;
    unsigned int                            size;
    unsigned char                           data[CTP_MOD_CLASSIFIER_MAX_PATTERN_SIZE];
    enum ctp_mod_classifier_pattern_mode    mode;
};

/* create an ethernet entity */
rv_t ctp_mod_classifier_create(const char *name, 
                               const enum ctp_mod_classifier_search_point user_id_search_point, 
                               const unsigned int user_id_offset, 
                               const struct ctp_mod_classifier_pattern *patterns, 
                               const unsigned int pattern_count,
                               handle_t *module);

/* set the unclassified output */
rv_t ctp_mod_classifier_set_unclassified_output(handle_t module, handle_t unclassified_output);

/* bind a classifier to specific per-user output */
rv_t ctp_mod_classifier_bind_user_handler(handle_t classifier_handle, 
                                          struct ctp_config_user *user,
                                          handle_t handler);

#endif /* __CTP_MOD_CLASSIFIER_H_ */

