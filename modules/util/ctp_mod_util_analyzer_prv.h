/* 
 * Analyzer utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_MOD_UTIL_ANALYZER_PRV_H_
#define __CTP_MOD_UTIL_ANALYZER_PRV_H_

#include "modules/util/ctp_mod_util_analyzer.h"
#include "modules/base/ctp_module.h"

/* ethernet module */
struct ctp_mod_util_analyzer
{
    struct ctp_module                   module;
    struct ctp_mod_util_analyzer_stats  stats;
};

#endif /* __CTP_MOD_UTIL_ANALYZER_PRV_H_ */
