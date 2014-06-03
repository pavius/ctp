/* 
 * Rx logger utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: July 25, 2011
 *
 */

#ifndef __CTP_LOG_RX_PRV_H_
#define __CTP_LOG_RX_PRV_H_

#include <semaphore.h>
#include "common/loggers/rx/ctp_log_rx.h"

/* the scheme for handling an event */
unsigned int ctp_log_rx_scheme;

/* log file, if specified */
FILE *ctp_log_rx_file;
FILE *ctp_pcap_rx_file;

/* sync semaphore */
sem_t ctp_log_sem;

#endif /* __CTP_LOG_RX_PRV_H_ */
