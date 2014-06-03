/* 
 * Rx logger utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: July 25, 2011
 *
 */

#ifndef __CTP_LOG_RX_H_
#define __CTP_LOG_RX_H_

#include "common/utils/common.h"
#include "modules/base/ctp_module.h"

/* schemes */
enum ctp_log_rx_scheme
{
    CTP_LOG_RX_SCHEME_ASSERT = (1 << 0),
    CTP_LOG_RX_SCHEME_COUNT  = (1 << 1),
    CTP_LOG_RX_SCHEME_LOG    = (1 << 2)
};

/* initialize rx logger */
rv_t ctp_log_rx_init(const unsigned int scheme);

/* handle events */
rv_t ctp_log_rx_event(struct ctp_module_message *message,
                      const char *format, ...);

/* shutdown rx logger */
rv_t ctp_log_rx_shutdown();

/* get logger file name. TODO: move to common */
void ctp_log_get_log_file_name(const char *log_type_name,
                               char *filename,
                               const unsigned int filename_size);

#endif /* __CTP_LOG_RX_H_ */
