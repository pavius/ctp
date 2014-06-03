/* 
 * Main module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h> 
#include <sched.h>
#include "ctp_prv.h"
#include "common/utils/assert.h"
#include "common/loggers/rx/ctp_log_rx.h"
#include "modules/base/ctp_module.h"
#include "modules/base/ctp_module_queue.h"
#include "modules/eth/ctp_mod_eth_rx.h"
#include "modules/eth/ctp_mod_eth_tx.h"
#include "modules/util/ctp_mod_util_analyzer.h"
#include "modules/classifier/ctp_mod_classifier.h"
#include "modules/rlc/ctp_mod_rlc_seg.h"
#include "modules/rlc/ctp_mod_rlc_ras.h"
#include "modules/iub/ctp_mod_iub_decap.h"
#include "modules/scheduler/ctp_mod_scheduler.h"

/* clear tail by outputting space */
static inline void ctp_ui_clear_line_tail(const unsigned int chars_written)
{
    unsigned int chars_to_write = 160 - chars_written;

    /* output */
    while (chars_to_write--) fputc(' ', stdout);
}

/* initialize gathering statistics */
void ctp_statistics_gather_init()
{
    /* zero out users with errors */
    memset(ctp_users_with_errors, 0, sizeof(ctp_users_with_errors));

    /* allocate two messages, essentially */
    ctp_stats_message = malloc(ctp_module_msg_size(CTP_MAX_STAT_MESSAGE_SIZE));
    ctp_stats_previous_message = malloc(ctp_module_msg_size(CTP_MAX_STAT_MESSAGE_SIZE));
    ctp_assert(ctp_stats_message != NULL && ctp_stats_previous_message != NULL, 
               "Failed to allocate stat message");

    /* initialize them */
    bzero(ctp_stats_message, ctp_module_msg_size(CTP_MAX_STAT_MESSAGE_SIZE));
    bzero(ctp_stats_previous_message, ctp_module_msg_size(CTP_MAX_STAT_MESSAGE_SIZE));

    /* initialize the messages */
    ctp_module_msg_init(ctp_stats_message, CTP_MAX_STAT_MESSAGE_SIZE);
    ctp_module_msg_init(ctp_stats_previous_message, CTP_MAX_STAT_MESSAGE_SIZE);
}

/* gather statistics */
void ctp_gather_module_statistics_to_message(struct ctp_module_message *message)
{
    unsigned int module_count;
    unsigned int module_index;
    handle_t module;

    /* initialize write pointers */
    ctp_module_msg_reset_write_state(message, 0);

    /* get number of modules */
    module_count = ctp_module_get_module_count();

    /* iterate through them */
    for (module_index = 0; module_index < module_count; ++module_index)
    {
        /* get the module */
        module = ctp_module_get_module_by_id(module_index);

        /* encode its statistics */
        ctp_module_encode_statistics(module, message);
    }
}

/* get mbps string from bytes/sec */
char* ctp_get_mbps_string_from_bytes_per_sec(const unsigned int bytes_per_sec,
                                             char *buffer,
                                             unsigned int buffer_length)
{
    float mbps;

    /* get bps */
    unsigned int bits_per_sec = bytes_per_sec * 8;

    /* convert to mbps */
    mbps = bits_per_sec / 1048510.0;

    /* now to string */
    snprintf(buffer, buffer_length, "%0.3f", mbps);
    buffer[buffer_length - 1] = '\0';

    /* return string */
    return buffer;
}

/* eth rx */
void ctp_print_eth_rx_stats(const unsigned char *current_stats, 
                            const unsigned char *previous_stats)
{
    struct ctp_mod_eth_rx_stats *cur_eth_stats = (struct ctp_mod_eth_rx_stats *)current_stats;
    struct ctp_mod_eth_rx_stats *prv_eth_stats = (struct ctp_mod_eth_rx_stats *)previous_stats;

    /* get mbps */
    ctp_get_mbps_string_from_bytes_per_sec(cur_eth_stats->rx_bytes - prv_eth_stats->rx_bytes, 
                                           ctp_mbps_string, sizeof(ctp_mbps_string));

    /* print stats */
    printf("total(f:%lld; b:%lld) @(%s Mbps; %lld f/s)", 
           cur_eth_stats->rx_frames, cur_eth_stats->rx_bytes,
           ctp_mbps_string,
           cur_eth_stats->rx_frames - prv_eth_stats->rx_frames);
}

/* eth tx */
void ctp_print_eth_tx_stats(const unsigned char *current_stats, 
                            const unsigned char *previous_stats)
{
    struct ctp_mod_eth_tx_stats *cur_eth_stats = (struct ctp_mod_eth_tx_stats *)current_stats;
    struct ctp_mod_eth_tx_stats *prv_eth_stats = (struct ctp_mod_eth_tx_stats *)previous_stats;

    /* get mbps */
    ctp_get_mbps_string_from_bytes_per_sec(cur_eth_stats->tx_bytes - prv_eth_stats->tx_bytes, 
                                           ctp_mbps_string, sizeof(ctp_mbps_string));

    /* print stats */
    printf("total(f:%lld; b:%lld) @(%s Mbps; %lld f/s)", 
           cur_eth_stats->tx_frames, cur_eth_stats->tx_bytes,
           ctp_mbps_string,
           cur_eth_stats->tx_frames - prv_eth_stats->tx_frames);
}

/* classifier */
void ctp_print_classifier_stats(const unsigned char *current_stats)
{

    struct ctp_mod_classifier_stats *stats = (struct ctp_mod_classifier_stats *)current_stats;

    /* print stats */
    printf("classified(%lld) unclassified(%lld)", stats->classified_frames, stats->unclassified_frames);
}

/* generator */
void ctp_print_generator_stats(const unsigned char *current_stats, 
                               const unsigned char *previous_stats)
{
}

/* analyzer */
void ctp_print_analyzer_stats(const unsigned char *current_stats, 
                              const unsigned char *previous_stats)
{
    struct ctp_mod_util_analyzer_stats *cur_ana_stats = (struct ctp_mod_util_analyzer_stats *)current_stats;
    struct ctp_mod_util_analyzer_stats *prv_ana_stats = (struct ctp_mod_util_analyzer_stats *)previous_stats;

    /* get mbps */
    ctp_get_mbps_string_from_bytes_per_sec(cur_ana_stats->rx_bytes - prv_ana_stats->rx_bytes, 
                                           ctp_mbps_string, sizeof(ctp_mbps_string)),

    /* print stats */
    printf("total(f:%lld; b:%lld) @(%s Mbps; %lld f/s)", 
           cur_ana_stats->rx_frames, cur_ana_stats->rx_bytes,
           ctp_mbps_string,
           cur_ana_stats->rx_frames - prv_ana_stats->rx_frames);
}

/* queue */
void ctp_print_queue_statistics(const unsigned char *current_stats, 
                                const unsigned char *previous_stats)
{
    struct ctp_module_queue_stats *cur_queue_stats = (struct ctp_module_queue_stats *)current_stats;

    /* print stats */
    printf("current(%d) high(%d)", 
           cur_queue_stats->msgq_message_count,
           cur_queue_stats->msgq_high_watermark);
}

/* decap statistics */
void ctp_save_iub_decap_statistics(const unsigned char *current_stats, 
                                   const unsigned char *previous_stats)
{
    /* just save pointer */
    ctp_module_per_user_stats.iub_decap = (struct ctp_mod_iub_decap_stats *)current_stats;
    ctp_module_prev_per_user_stats.iub_decap = (struct ctp_mod_iub_decap_stats *)previous_stats;
}

/* ras statistics */
void ctp_save_rlc_ras_statistics(const unsigned char *current_stats, 
                                 const unsigned char *previous_stats)
{
    /* just save pointer */
    ctp_module_per_user_stats.rlc_ras = (struct ctp_mod_rlc_ras_stats *)current_stats;
    ctp_module_prev_per_user_stats.rlc_ras = (struct ctp_mod_rlc_ras_stats *)previous_stats;
}

/* seg statistics */
void ctp_save_rlc_seg_statistics(const unsigned char *current_stats, 
                                 const unsigned char *previous_stats)
{
    /* just save pointer */
    ctp_module_per_user_stats.rlc_seg = (struct ctp_mod_rlc_seg_stats *)current_stats;
    ctp_module_prev_per_user_stats.rlc_seg = (struct ctp_mod_rlc_seg_stats *)previous_stats;
}

/* sched statistics */
void ctp_save_scheduler_statistics(const unsigned char *current_stats, 
                                   const unsigned char *previous_stats)
{
    /* just save pointer */
    ctp_module_per_user_stats.scheduler = (struct ctp_mod_scheduler_stats *)current_stats;
    ctp_module_prev_per_user_stats.scheduler = (struct ctp_mod_scheduler_stats *)previous_stats;
}

/* print module statistics */
void ctp_print_module_statistics(struct ctp_module *module, 
                                 struct ctp_module_message *message, 
                                 struct ctp_module_message *previous_message,
                                 const unsigned int offset)
{
    char name_buffer[256];
    unsigned char *current_stats, *previous_stats;

    /* print module type and id */
    snprintf(name_buffer, sizeof(name_buffer), "%s (%s): ", 
             module->name, ctp_module_get_type_name(module->type));

    /* terminate name */
    name_buffer[sizeof(name_buffer) - 1] = '\0';

    /* print name, left aligned if not per-user */
    if (module->stats_per_user == false) 
        printf("%02d: %21s", module->id, name_buffer);

    /* get pointers to current/previous stats */
    current_stats = &message->data[offset];
    previous_stats = &previous_message->data[offset];

    /* according to module */
    switch (module->type)
    {
        case CTP_MODTYPE_ETH_RX:         ctp_print_eth_rx_stats(current_stats, previous_stats);                   break;
        case CTP_MODTYPE_ETH_TX:         ctp_print_eth_tx_stats(current_stats, previous_stats);                   break;
        case CTP_MODTYPE_CLASSIFIER:     ctp_print_classifier_stats(current_stats);                               break;
        case CTP_MODTYPE_UTIL_ANALYZER:  ctp_print_analyzer_stats(current_stats, previous_stats);                 break;
        case CTP_MODTYPE_BASE_QUEUE:     ctp_print_queue_statistics(current_stats, previous_stats);               break;   
        case CTP_MODTYPE_RLC_RAS:        ctp_save_rlc_ras_statistics(current_stats, previous_stats);              break;
        case CTP_MODTYPE_RLC_SEG:        ctp_save_rlc_seg_statistics(current_stats, previous_stats);              break;
        case CTP_MODTYPE_IUB_DECAP:      ctp_save_iub_decap_statistics(current_stats, previous_stats);            break;
        case CTP_MODTYPE_SCHEDULER:      ctp_save_scheduler_statistics(current_stats, previous_stats);            break;
                
        /* unsupported module */
        default:
            ctp_assert(0, "Unsupported module for statistics");
            return;
    }
}

/* print nodebs */
void ctp_print_nodebs()
{
    struct ctp_config_nodeb *nodeb;
    char str_buffer[256];

    /* space out */
    printf("\n");

    /* iterate through nodebs */
    TAILQ_FOREACH(nodeb, &ctp_config_get()->nodeb_list, config_entry)
    {
        /* print nodeb info */
        printf("NodeB@%s: max-tti(%lld) tti-histogram(%lld %lld %lld %lld %lld) common-credits(%d)\n", 
               ip_addr_to_str(nodeb->ip_address, str_buffer, sizeof(str_buffer)),
               nodeb->max_schedule_interval,
               nodeb->schedule_interval_histogram[0], nodeb->schedule_interval_histogram[1],
               nodeb->schedule_interval_histogram[2], nodeb->schedule_interval_histogram[3],
               nodeb->schedule_interval_histogram[4],
               nodeb->common_leftover_credits);
    }
}

/* print a counter in red if non-zero */
#define ctp_print_counter_check_error(counter)                        \
    (counter) ? CTP_COLOR_BRIGHT CTP_COLOR_RED : CTP_COLOR_RESET,     \
    (counter),                                                        \
    CTP_COLOR_RESET                                     

/* print per user statistics */
void ctp_print_module_per_user_statistics()
{
    unsigned int uidx, users_with_errors;
    struct ctp_config_user *user;
    char str_buffer[256], *seg_tx_mbps;
    unsigned long long seg_sdus_sec;
    struct ctp_module_per_user_stats_data *curr_stats = &ctp_module_per_user_stats,
                                          *prev_stats = &ctp_module_prev_per_user_stats;

    /* header */
    printf("\n%sUsers:\n", ctp_current_selected_section == ctp_css_users ? "* " : "");

    /* title */
    snprintf(str_buffer, sizeof(str_buffer) - 1,
            "%6s | %15s| %15s| %9s| %8s| %15s| %10s| %10s| %15s| %20s\n", 
            "user ", 
            "address   ", "tx-pdus   ", "tx-mbps ", "tx-f/s ", 
            "rx-pdus    ", "pkt-loss ", "pkt-ooo  ", "pdu-oos     ", "rx-err     ");

    /* print the buffer */
    fputs(str_buffer, stdout);

    /* separator */
    for (uidx = 0; uidx < strlen(str_buffer); ++uidx) fputc('-', stdout);
    fputc('\n', stdout);

    /* iterate through all users */
    for (uidx = 0; 
          uidx < ctp_config_get_active_users_count(); 
          ++uidx)
    {
        /* find user */
        user = ctp_config_get_active_user_by_index(uidx);

        /* does user have reassembly and decap? */
        if (curr_stats->rlc_ras && curr_stats->iub_decap)
        {
            /* set whether the user has an error */
            ctp_users_with_errors[uidx] = curr_stats->rlc_ras[uidx].oos_pdus ||
                                          curr_stats->iub_decap[uidx].not_enough_data_l2 ||
                                          curr_stats->rlc_ras[uidx].not_enough_data_pdu ||
                                          curr_stats->rlc_ras[uidx].invalid_pdu_size;
        }

        /* is this user's statistics supposed to be displayed? */
        if (uidx >= ctp_user_stats_start_index && uidx < ctp_user_stats_start_index + 25)
        {
            /* is there a segmentation module? */
            if (curr_stats->rlc_seg && prev_stats->rlc_seg)
            {
                /* sdus/sec */
                seg_sdus_sec = curr_stats->rlc_seg[uidx].inputted_sdus - 
                               prev_stats->rlc_seg[uidx].inputted_sdus;

                /* get mbps */
                seg_tx_mbps = ctp_get_mbps_string_from_bytes_per_sec(curr_stats->rlc_seg[uidx].inputted_bytes - 
                                                                     prev_stats->rlc_seg[uidx].inputted_bytes, 
                                                                     ctp_mbps_string, sizeof(ctp_mbps_string));
            }
            else
            {
                seg_sdus_sec = 0;
                seg_tx_mbps = "N/A";
            }

            /* print user */
            printf("%6d |%15s |%15lld |%9s |%8lld |%15lld |%s%10lld%s |%s%10lld%s |%s%15lld%s |", 
                   user->index,
                   ip_addr_to_str(user->ip_addr, str_buffer, sizeof(str_buffer)), 
                   curr_stats->rlc_seg ? curr_stats->rlc_seg[uidx].tx_pdus : 0,
                   seg_tx_mbps,
                   seg_sdus_sec,
                   curr_stats->rlc_ras ? curr_stats->rlc_ras[uidx].rx_pdus : 0,
                   ctp_print_counter_check_error(curr_stats->iub_decap ? curr_stats->iub_decap[uidx].oos_frames : 0),
                   ctp_print_counter_check_error(curr_stats->iub_decap ? curr_stats->iub_decap[uidx].possibly_reordered_frames : 0),
                   ctp_print_counter_check_error(curr_stats->rlc_ras ? curr_stats->rlc_ras[uidx].oos_pdus : 0));

            /* print queue size */
            if (curr_stats->scheduler)
            {
                printf("%lld:%lld:%d", curr_stats->scheduler[uidx].queued_bytes, 
                       curr_stats->scheduler[uidx].max_queued_bytes,
                       user->pdu_q_leftover_credits);
            }
            else
            {
                /* if we need to count errors */
                if (ctp_config_get()->rx_err_scheme & CTP_LOG_RX_SCHEME_COUNT && 
                    curr_stats->iub_decap &&
                    curr_stats->rlc_ras)
                {
                    int error_counter_length, idx;

                    /* Really annoying code below. Width specifier for %s takes the ansi escape codes
                     * into consideration so we must perform right align ourselves
                     */

                    /* get error string without colors so that we can get the length */
                    snprintf(str_buffer, sizeof(str_buffer) - 1,
                             "%lld:%lld:%lld", 
                             curr_stats->iub_decap[uidx].not_enough_data_l2,
                             curr_stats->rlc_ras[uidx].not_enough_data_pdu,
                             curr_stats->rlc_ras[uidx].invalid_pdu_size);

                    /* get length */
                    error_counter_length = strlen(str_buffer);

                    /* now print errors with color */
                    snprintf(str_buffer, sizeof(str_buffer) - 1,
                             "%s%lld%s:%s%lld%s:%s%lld%s", 
                             ctp_print_counter_check_error(curr_stats->iub_decap[uidx].not_enough_data_l2),
                             ctp_print_counter_check_error(curr_stats->rlc_ras[uidx].not_enough_data_pdu),
                             ctp_print_counter_check_error(curr_stats->rlc_ras[uidx].invalid_pdu_size));

                    /* align counter left */
                    for (idx = 0; idx < get_maximum(21 - error_counter_length, 0); ++idx) fputc(' ', stdout);

                    /* print invalid */
                    printf("%s", str_buffer);
                }
                else
                {
                    /* no counting */
                    printf("%21s", "N/A");
                }
            }

            /* space out */
            printf("\n");
        }
    }

    /* print */
    printf("\nUsers with errors: ");

    /* print users with errors */
    for (uidx = 0, users_with_errors = 0; 
          uidx < ctp_config_get_active_users_count() && users_with_errors < 50; 
          ++uidx)
    {
        /* check if user has error */
        if (ctp_users_with_errors[uidx])
        {
            printf("%d, ", ctp_config_get_active_user_by_index(uidx)->index);
            users_with_errors++;
        }
    }

    /* no users with errors? */
    if (users_with_errors == 0)
    {
        printf("None");
    }

    /* space out */
    printf("\n");
}

/* reset all data in stat message */
void ctp_reset_module_statistics_message(struct ctp_module_message *message)
{
    unsigned char *current_pos, *end_pos;
    struct ctp_module_stat_header stat_header;

    /* get current position */
    current_pos = ctp_module_msg_get_head(message);

    /* get end position */
    end_pos = (current_pos + ctp_module_msg_get_bytes_written(message));

    /* while there is still stuff left to read */
    while (current_pos < end_pos)
    {
        /* get the module id */
        ctp_assert(end_pos - current_pos >= sizeof(struct ctp_module_stat_header), "Not enough data for header");
        memcpy(&stat_header, current_pos, sizeof(struct ctp_module_stat_header));

        /* skip id */
        current_pos += sizeof(stat_header);

        /* zero out stats */
        memset(current_pos, 0, stat_header.size);

        /* skip over module statistics */
        current_pos += stat_header.size;
    }
}

/* print module statistics. packet will hold [module-id][module-stats] */
void ctp_print_module_statistics_message(struct ctp_module_message *message, 
                                         struct ctp_module_message *previous_message)
{
    unsigned char *current_pos;
    unsigned char *end_pos;
    struct ctp_module_stat_header stat_header;
    struct ctp_module *module;

    /* header */
    printf("Modules:\n");

    /* get current position */
    current_pos = ctp_module_msg_get_head(message);

    /* get end position */
    end_pos = (current_pos + ctp_module_msg_get_bytes_written(message));

    /* while there is still stuff left to read */
    while (current_pos < end_pos)
    {
        /* get the module id */
        ctp_assert(end_pos - current_pos >= sizeof(struct ctp_module_stat_header), "Not enough data for header");
        memcpy(&stat_header, current_pos, sizeof(struct ctp_module_stat_header));

        /* skip id */
        current_pos += sizeof(stat_header);

        /* try to get the module */
        module = ctp_module_get_module_by_id(stat_header.id);
        ctp_assert(module, "Invalid module id in packet");

        /* print the module statistics */
        ctp_print_module_statistics(module, 
                                    message, previous_message,
                                    current_pos - ctp_module_msg_get_head(message));

        /* print only non-per user modules. per-user stuff is printed later */
        if (module->stats_per_user == false)
        {
            /* space out, erasing any old data */
            printf("\n");
        }

        /* skip over module statistics */
        current_pos += stat_header.size;
    }
}

/* print statistics */
void ctp_statistics_reset()
{
    unsigned int module_count;
    unsigned int module_index;
    handle_t module;
    struct ctp_config_nodeb *nodeb;

    /* get number of modules */
    module_count = ctp_module_get_module_count();

    /* iterate through them */
    for (module_index = 0; module_index < module_count; ++module_index)
    {
        /* get the module */
        module = ctp_module_get_module_by_id(module_index);

        /* reset its statistics */
        ctp_module_reset_statistics(module);
    }

    /* zero out previous statistics as well */
    if (ctp_stats_message && ctp_stats_previous_message)
    {
        /* zero out the statistics message */
        ctp_reset_module_statistics_message(ctp_stats_message);
        ctp_reset_module_statistics_message(ctp_stats_previous_message);
    }

    /* zero out users with errors */
    memset(ctp_users_with_errors, 0, sizeof(ctp_users_with_errors));

    /* iterate through nodebs */
    TAILQ_FOREACH(nodeb, &ctp_config_get()->nodeb_list, config_entry)
    {
        /* reset counter */
        nodeb->max_schedule_interval = 0;
    }

    /* refresh teh screen */
    ctp_refresh_screen();
}

/* print banner */
void ctp_print_banner()
{
    /* print banner */
    printf("Convoluted Traffic Processor v.%s (compiled %s %s)\n", CTP_VERSION, __TIME__, __DATE__);

/* print simulation warning */
#ifdef CTP_SIMULATION
    printf(CTP_COLOR_BRIGHT "WARNING: Running in simulation mode\n" CTP_COLOR_RESET);
#endif
}

/* print configuration */
void ctp_print_configuration()
{
    unsigned int line_index = 0;

    /* print the configuration */
    printf("%sConfiguration (@%s):\n", 
           ctp_current_selected_section == ctp_css_config ? "* " : "", 
           ctp_config_get()->config_file);

    /* iterate through configuration lines */
    for (line_index = ctp_config_start_index; 
          line_index < ctp_config_get()->descriptor_lines && 
          line_index < (ctp_config_start_index + 10); 
          ++line_index)
    {
        /* do the print */
        printf("%s", ctp_config_get()->descriptor_string[line_index]);
    }
}

/* print screen */
void ctp_refresh_screen()
{
    /* reset cursor */
    printf(CTP_CLR_SCR);

    /* print banner */
    ctp_print_banner();

    /* space out */
    printf("\n");

    /* print configuration */
    ctp_print_configuration();

    /* space out */
    printf("\n");

    /* print modules */ 
    ctp_print_module_statistics_message(ctp_stats_message, ctp_stats_previous_message);

    /* print nodebs */
    ctp_print_nodebs();

    /* print user statistics */
    ctp_print_module_per_user_statistics();

    /* print hr log status */
    ctp_log_event_print_logs_status();

    /* print help message */
    if (!ctp_currently_inputting)
    {
        /* static header */
        printf("\n(Q)uit  (R)eset statistics  (J)ump to user\n");
    }
    else
    {
        /* pritn what user is writing */
        printf("\n%s%s", ctp_input_field_label, ctp_input_field);
    }
}

/* set at which position we want to print the user statistics */
void ctp_update_user_stats_start_index(int new_value)
{
    /* update user */
    ctp_user_stats_start_index = new_value;

    /* check if overflows (towards negative will wrap to max_int */
    if (ctp_user_stats_start_index > (int)ctp_config_get_active_users_count() - 1)
    {
        /* set max */
        ctp_user_stats_start_index = ctp_config_get_active_users_count() - 1;
    }   
    else if (ctp_user_stats_start_index < 0)
    {
        /* set min */
        ctp_user_stats_start_index = 0;
    }

    /* refresh screen */
    ctp_refresh_screen();
}

/* set at which position we want to print the configuration */
void ctp_update_config_start_index(int new_value)
{
    /* update user */
    ctp_config_start_index = new_value;

    /* check if overflows (towards negative will wrap to max_int */
    if (ctp_config_start_index > (int)ctp_config_get()->descriptor_lines - 1)
    {
        /* set max */
        ctp_config_start_index = ctp_config_get()->descriptor_lines - 1;
    }   
    else if (ctp_config_start_index < 0)
    {
        /* set min */
        ctp_config_start_index = 0;
    }

    /* refresh screen */
    ctp_refresh_screen();
}

/* scroll current section up */
void ctp_scroll_up(const unsigned int count)
{
    if (ctp_current_selected_section == ctp_css_config)     ctp_update_config_start_index(ctp_config_start_index - count);
    else if (ctp_current_selected_section == ctp_css_users) ctp_update_user_stats_start_index(ctp_user_stats_start_index - count);
}

/* scroll current section down */
void ctp_scroll_down(const unsigned int count)
{
    if (ctp_current_selected_section == ctp_css_config)     ctp_update_config_start_index(ctp_config_start_index + count);
    else if (ctp_current_selected_section == ctp_css_users) ctp_update_user_stats_start_index(ctp_user_stats_start_index + count);
}

/* get the line in the config descriptor holding a specific user */
bool ctp_get_config_desc_line_by_user_id(const unsigned int user_id, unsigned int *line)
{
    unsigned int line_index = 0, search_string_len;
    char search_string[128];

    /* format the string (gross) */
    snprintf(search_string, sizeof(search_string) - 1,
             "  user[%d]", user_id);

    /* get length */
    search_string_len = strlen(search_string);

    /* iterate over descriptor lines */
    for (line_index = 0; line_index < ctp_config_get()->descriptor_lines; ++line_index)
    {
        /* is this the current row? */
        if (memcmp(search_string, 
                   ctp_config_get()->descriptor_string[line_index], 
                   search_string_len) == 0)
        {
            /* done */
            *line = line_index;
            return true;
        }
    }

    /* not found */
    return false;
}

/* input data to input file */
bool ctp_read_input_data(char *input_data, 
                         const unsigned int input_data_size,
                         const bool numeric_only)
{
    bool done = false, success = true;
    int current_index;

    /* init index into input_data */
    current_index = 0;

    /* block */
    while (!done && (current_index < input_data_size - 1))
    {
        /* get input */
        char input_char = getchar();

        /* printf(" *** %d *** ", input_char); */
    }

    /* terminate string */
    input_data[current_index] = '\0';

    /* return if user canceled or not */
    return success;
}

/* */
void ctp_scroll_to_user_from_string(const char *input_field)
{
    unsigned int value;

    /* try to convert to int */
    if (str_to_uint(input_field, &value) == RV_OK)
    {
        /* jump to user in configuration */
        if (ctp_current_selected_section == ctp_css_config)     
        {
            unsigned int line;

            /* get config descriptor line by user */
            if (ctp_get_config_desc_line_by_user_id(value, &line))
            {
                ctp_update_config_start_index(line);
            }
        }
        /* jump to user in user stats */
        else if (ctp_current_selected_section == ctp_css_users) 
        {
            /* jump to its index */
            ctp_update_user_stats_start_index(value);
        }
    }
}

/* enter inputting user state */
void ctp_start_inputting_user_id()
{
    /* zero out input */
    memset(ctp_input_field, 0, sizeof(ctp_input_field));
    ctp_input_field_index = 0;

    /* set inputting flag */
    ctp_currently_inputting = true;
    ctp_input_field_label = "User id: ";
}

/* move selected section to next */
void ctp_select_next_section()
{
    /* select next */
    if (++ctp_current_selected_section >= ctp_css_max)
    {
        /* overflow - set to first */
        ctp_current_selected_section = ctp_css_config;
    }

    /* refresh screen */
    ctp_refresh_screen();
}

/* distribute message to clients */
void ctp_distribute_statistics_to_clients(struct ctp_module_message *message)
{
    unsigned int client_index = 0;
    bool result;
    struct ctp_stats_header header;
        header.magic_number = 0x01090607;
        header.version      = 1;
        header.size         = ctp_module_msg_get_bytes_written(message);

    /* iterate over clients */
    for (client_index = 0; client_index < array_size(ctp_stat_clients); ++client_index)
    {
        /* is there an active client? */
        if (ctp_stat_clients[client_index] != -1)
        {
            /* send the header and message */
            result = send(ctp_stat_clients[client_index], &header, sizeof(header), MSG_NOSIGNAL) > 0 && 
                     send(ctp_stat_clients[client_index], message->data, header.size, MSG_NOSIGNAL) > 0;

            /* check if error */
            if (!result)
            {
                /* close socket */
                close(ctp_stat_clients[client_index]);
                ctp_stat_clients[client_index] = -1;
            }
        }
    }
}

/* called every 1 second */
void ctp_handle_timer_expiration()
{
    struct ctp_module_message *temp;

    /* swap current/previous so that next time we fill up current */
    temp = ctp_stats_message;
    ctp_stats_message = ctp_stats_previous_message;
    ctp_stats_previous_message = temp;

    /* gather stats from modules */
    ctp_gather_module_statistics_to_message(ctp_stats_message);

    /* distribute the statistics to clients */
    // ctp_distribute_statistics_to_clients(ctp_stats_message);

    /* print statistics */
    ctp_refresh_screen();
}

/* cleanup */
void ctp_shutdown(void)
{
    struct termios stdout_termios;

    /* return the terminal back to normal */
    tcgetattr(STDIN_FILENO, &stdout_termios);
    stdout_termios.c_lflag |= (ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &stdout_termios);

    /* shutdown log */
    ctp_log_rx_shutdown();

    /* shutdown stat listener */
    ctp_shutdown_stat_listener();
}

/* assert handler */
void ctp_handle_assert(const char *descriptor)
{
    void *backtrace_items[200];
    size_t backtrace_item_count;
    char crash_file_name[256];
    int assert_log_file;

    /* save call stack */
    backtrace_item_count = backtrace(backtrace_items, sizeof(backtrace_items));

    /* get file name (creates log dir if doesn't exist) */
    ctp_log_get_log_file_name("assert.log",
                               (char *)&crash_file_name,
                               sizeof(crash_file_name));
    
    /* let the user know */
    printf("Dumping call stack (%d rows) to %s ... ", backtrace_item_count, crash_file_name);

    /* open the file */
    assert_log_file = open(crash_file_name, O_CREAT | O_RDWR, 
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    /* if successfully opened the file */
    if (assert_log_file != -1)
    {
        /* write header */
        if (write(assert_log_file, descriptor, strlen(descriptor)) != -1 && 
            write(assert_log_file, "\n", 1) != -1)
        {
            /* save backtrace */
            backtrace_symbols_fd(backtrace_items, backtrace_item_count, assert_log_file);

            /* success */
            printf("Done.\n");
        }
        else
        {
            /* couldn't write to file for some reason */
            printf("Failed (couldn't write to file)\n");
        }
    }
    else
    {
        /* couldn't open file for some reason */
        printf("Failed (couldn't open file)\n");
    }

    /* close the file if created */
    if (assert_log_file != -1) close(assert_log_file);

    /* cleanup */
    ctp_shutdown();

/* debug */
#ifndef NDEBUG

	/* raise debugger int */
    asm("int $3");

    /* block */
    while(1);

/* release */
#else

    /* and exit */
    exit(1);
#endif
}

/* handle control+c */
void ctp_handle_ctrl_c(int sig)
{
    /* cleanup */
    ctp_shutdown();

    /* and exit */
    exit(1);
}

/* initialize statistics listener */
void ctp_init_stat_listener()
{
    struct sockaddr_in stat_address;
    int result;
    int option_value;
    cpu_set_t mask;

    /* create the socket */
    ctp_stat_socket = socket(AF_INET, SOCK_STREAM, 0);
    ctp_assert(ctp_stat_socket != -1, "Failed to create stat socket");

    /* init address */
    bzero(&stat_address, sizeof(stat_address));
        stat_address.sin_family         = AF_INET;
        stat_address.sin_addr.s_addr    = INADDR_ANY;
        stat_address.sin_port           = htons(1967);

    /* reuse the port if in time_wait */
    option_value = 1;
    result = setsockopt(ctp_stat_socket, SOL_SOCKET, SO_REUSEADDR, &option_value, sizeof(option_value));
    ctp_assert(result == 0, "Failed to set stat socket options");

    /* bind statistics socket listener */
    result = bind(ctp_stat_socket, (struct sockaddr *)&stat_address, sizeof(stat_address));
    ctp_assert(result != -1, "Failed to bind stat socket");

    /* listen for connections */
    result = listen(ctp_stat_socket, 3);
    ctp_assert(result != -1, "Failed to listen on stat socket");

    /* init mask */
    CPU_ZERO(&mask);

    /* run ui thread @ cpu 0 */
    CPU_SET(0, &mask);

    /* set affinity */
    ctp_assert(sched_setaffinity(0, sizeof(mask), &mask) == 0, "Failed to set affinity");
}

/* shutdown stat listener */
void ctp_shutdown_stat_listener()
{
    unsigned int client_index;

    /* if socket is initialized */
    if (ctp_stat_socket != -1)
    {
        /* close it */
        close(ctp_stat_socket);

        /* close all clients */
        for (client_index = 0; client_index < array_size(ctp_stat_clients); ++client_index)
        {
            /* is there an active client? */
            if (ctp_stat_clients[client_index] != -1)
            {
                /* close it */
                close(ctp_stat_clients[client_index]);
            }
        }
    }
}

/* initialize system */
void ctp_init()
{
    struct termios stdout_termios;

    /* register ctrl+c handler */
    signal (SIGINT, ctp_handle_ctrl_c);

    /* Set unbuffered stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* don't echo chars */
    tcgetattr(STDIN_FILENO, &stdout_termios);
    stdout_termios.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &stdout_termios);

    /* zero out stat clients */
    memset(ctp_stat_clients, 0xFF, sizeof(ctp_stat_clients));

    /* seed rng */
    srand(time(NULL));

    /* initialize stat gathering */
    ctp_statistics_gather_init();

    /* initialize listener */
    // ctp_init_stat_listener();

    /* initialize config */
    ctp_config_init();
}

/* handle stdin while inputting user */
void ctp_inputting_user_id_handle_stdin_input(const char input_char, 
                                              unsigned char *input_data,
                                              unsigned int *input_data_index)
{
    bool done = false;

    /* is it an exit sequence? */
    if (input_char == '\r' || input_char == '\n')
    {
        /* jump to the user */
        ctp_scroll_to_user_from_string(input_data);

        /* we're done */
        done = true;
    }
    /* backspace */
    else if (input_char == 127)
    {
        /* decrement index */
        if (--(*input_data_index) < 0) (*input_data_index) = 0;
        input_data[(*input_data_index)] = '\0';
    }
    else if (input_char == 27)
    {
        /* done */
        done = true;
    }
    else
    {
        /* check if number */
        if (isdigit(input_char)) 
        {
            /* shove to input data */
            input_data[(*input_data_index)++] = input_char;
        }
    }

    /* if we're done, exit */
    if (done) ctp_currently_inputting = false;

    /* refresh the screen */
    ctp_refresh_screen();
}

/* handle stdin while running */
void ctp_running_handle_stdin_input(const char input_char, bool *done)
{
    /* according to command */
    switch (tolower(input_char))
    {
        /* reset statistics */
        case 'r':
            ctp_statistics_reset();
            break;

        /* exit */
        case 'q':
            *done = true;
            break;

        /* prev user */
        case 'y':
            ctp_scroll_up(1);
            break;

        /* next user */
        case 'h':
            ctp_scroll_down(1);
            break;

		/* prev user */
		case 't':
			ctp_scroll_up(25);
			break;

		/* next user */
		case 'g':
			ctp_scroll_down(25);
			break;

        /* next section */
        case '\t':
            ctp_select_next_section();
            break;

        /* jump to user */
        case 'j':
            /* enter state */
            ctp_start_inputting_user_id();

            /* refresh */
            ctp_refresh_screen();
            break;
   }
}

/* handle case in which user pressed something */
void ctp_handle_stdin_input(bool *done)
{
    /* get input */
    char input_char = getchar();

    /* according to state */
    if (!ctp_currently_inputting)
    {
        /* handle input */
        ctp_running_handle_stdin_input(input_char, done);
    }
    else
    {
        /* handle input */
        ctp_inputting_user_id_handle_stdin_input(input_char, 
                                                 ctp_input_field, 
                                                 &ctp_input_field_index);
    }
}

/* initialize event sources */
void ctp_init_event_sources(fd_set *fds, struct timeval *timeout)
{
    /* initialize event sources */
    FD_ZERO(fds);

    /* add stdin and listener queue */
    FD_SET(0, fds);
    // FD_SET(ctp_stat_socket, fds);

    /* init timeout */
    timeout->tv_sec = 1;
    timeout->tv_usec = 0;
}

/* process pending events on blockable objects */
void ctp_process_events()
{
    bool done = false;
    fd_set event_sources;
    int result;
    struct timeval timeout;
    int new_stat_client, client_address_size;
    struct sockaddr_in client_address;

    /* init the event sources */
    ctp_init_event_sources(&event_sources, &timeout);

    /* block */
    while (!done)
    {
        /* wait on descriptors */
        result = select(0 + 1, &event_sources, NULL, NULL, &timeout);

        /* check if error */
        if (result > 0)
        {
			/* check which event occured */
			if (FD_ISSET(0, &event_sources))
			{
				/* handle in keystroke handler */
				ctp_handle_stdin_input(&done);
			}
            else if (FD_ISSET(ctp_stat_socket, &event_sources))
            {
                /* accept new client */
                client_address_size = sizeof(client_address_size);
                new_stat_client = accept(ctp_stat_socket, (struct sockaddr *)&client_address, &client_address_size);

                /* accept if we have room */
                if (ctp_stat_clients[0] == -1)
                {
                    /* save it */
                    ctp_stat_clients[0] = new_stat_client;
                }
                else
                {
                    /* reject it */
                    close(new_stat_client);
                }
            }
        }
        /* check if timeout occured */
        else if (result == 0)
        {
            /* call timer */
            ctp_handle_timer_expiration();

            /* init the event sources */
            ctp_init_event_sources(&event_sources, &timeout);
        }
        /* another error */
        else if (errno != EINTR)
        {
            /* error */
            perror("Select failed");
            ctp_assert(0, "Failed to read device");
        }
    }
}

/* entry */
int main(int argc, char *argv[])
{
    /* print the banner */
    ctp_print_banner();

    /* check arguments */
    if (argc != 2)
    {
        /* print usage and bail */
        printf("Usage ctp <config-file>\n");
        exit(1);
    }

    /* check if we're root */
    if ((getuid () && geteuid ()) || setuid (0))
    {
        /* log and exit */
        printf ("Must run as root\n");
        exit(1);
    }
    
    /* initialize */
    ctp_init();

    /* parse the configuration and init rx log */
    if (ctp_config_parse_file(argv[1]) == RV_OK && 
        ctp_log_rx_init(ctp_config_get()->rx_err_scheme) == RV_OK)
    {
        /* execute the configuration */
        ctp_config_execute();

        /* gather stats from modules */
        ctp_gather_module_statistics_to_message(ctp_stats_message);

        /* refresh screen output */
        ctp_refresh_screen();

        /* process events (blocks until done) */
        ctp_process_events();
    }

    /* shut down */
    ctp_shutdown();

    /* done */
    return 0;
}

