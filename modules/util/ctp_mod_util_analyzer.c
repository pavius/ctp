/* 
 * Analyzer utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <zlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include "common/utils/assert.h"
#include "modules/util/ctp_mod_util_analyzer_prv.h"
#include "modules/base/ctp_module_msgpool.h"

/* process a message */
void ctp_mod_util_analyzer_process_message(struct ctp_module *module, 
                                           struct ctp_module_message *message)
{
    unsigned int sdu_length;
    unsigned calculated_crc;
    struct ctp_mod_util_analyzer_header generator_header;
    static unsigned int expected_seqnum = 0;

    /* get generator */
    struct ctp_mod_util_analyzer *analyzer = (struct ctp_mod_util_analyzer *)module;

    /* get message length */
    sdu_length = ctp_module_msg_get_bytes_written(message);

    /* read the crc */
    memcpy(&generator_header, 
           ctp_module_msg_get_head(message) + sdu_length - sizeof(generator_header), 
           sizeof(generator_header));

    /* to host */
    generator_header.crc = ntohl(generator_header.crc);
    generator_header.seqnum = ntohl(generator_header.seqnum);

    /* calculate crc over the message */
    calculated_crc = crc32(0, NULL, 0);
    calculated_crc = crc32(calculated_crc, 
                           ctp_module_msg_get_head(message), 
                           sdu_length - sizeof(generator_header));

    /* make sure they match */
    ctp_assert(generator_header.crc == calculated_crc, "Invalid payload received");

    /* expect next seqnum */
    expected_seqnum++;

    /* free the message */
    ctp_module_msgpool_free_msg(message);

    /* increment statistics */
    analyzer->stats.rx_frames++;
    analyzer->stats.rx_bytes += sdu_length;
}

/* create an ethernet entity */
rv_t ctp_mod_util_analyzer_create(handle_t *module)
{
    rv_t result;
    struct ctp_mod_util_analyzer *analyzer;

    /* create base object */
    result = ctp_module_create(sizeof(struct ctp_mod_util_analyzer), 
                               CTP_MODTYPE_UTIL_ANALYZER, "Ana", module);

    /* call base */
    if (result == RV_OK)
    {
        /* set xmitter stuff */
        analyzer = (struct ctp_mod_util_analyzer *)(*module);
            ctp_module_set_process_message(analyzer, ctp_mod_util_analyzer_process_message);
            ctp_module_register_stats(&analyzer->module, 
                                      (unsigned char *)&analyzer->stats, 
                                      sizeof(analyzer->stats));
    }

    /* return the result */
    return result;
}

