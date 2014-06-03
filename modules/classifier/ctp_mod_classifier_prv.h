/* 
 * Ethernet classifier module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_CLASSIFIER_PRV_H_
#define __CTP_MOD_CLASSIFIER_PRV_H_

#include "modules/classifier/ctp_mod_classifier.h"
#include "modules/base/ctp_module.h"

/* max pattern length in bytes */
#define CTP_MOD_CLASSIFIER_MAX_PATTERNS (4)

/* ethernet module */
struct ctp_mod_classifier
{
    struct ctp_module                       module;
    unsigned char                           id;
    unsigned int                            user_id_offset;
    enum ctp_mod_classifier_search_point    user_id_search_point;
    struct ctp_mod_classifier_pattern       patterns[CTP_MOD_CLASSIFIER_MAX_PATTERNS];
    unsigned int                            pattern_count;
    struct ctp_module                       *unclassified_output;
    struct ctp_mod_classifier_stats         stats;
};

#endif /* __CTP_MOD_CLASSIFIER_PRV_H_ */
