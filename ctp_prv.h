/* 
 * Main module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: July 30, 2011
 *
 */

#ifndef __CTP_PRV_H_
#define __CTP_PRV_H_

#include <mqueue.h>
#include "config/ctp_config.h"

/* 
 * constants
 */

/* escape codes */
#define CTP_RESET_CURSOR      "\033[H"
#define CTP_ERASE_LINE        "\033[K"
#define CTP_CLR_SCR           "\033[2J"
#define CTP_COLOR_RESET       "\033[0m"
#define CTP_COLOR_BRIGHT      "\033[1m"
#define CTP_COLOR_BLACK       "\033[30m"             /* Black */
#define CTP_COLOR_RED         "\033[31m"             /* Red */
#define CTP_COLOR_GREEN       "\033[32m"             /* Green */
#define CTP_COLOR_YELLOW      "\033[33m"             /* Yellow */
#define CTP_COLOR_BLUE        "\033[34m"             /* Blue */
#define CTP_COLOR_MAGENTA     "\033[35m"             /* Magenta */
#define CTP_COLOR_CYAN        "\033[36m"             /* Cyan */
#define CTP_COLOR_WHITE       "\033[37m"             /* White */
#define CTP_COLOR_BOLD        "\033[1m"              /* Bold */

/* version string */
#define CTP_VERSION "0.2.6"

/* max statistics message */
#define CTP_MAX_STAT_MESSAGE_SIZE (16 * 1024 * 1024)

/* 
 * locals
 */

/* statistics message - modules will encode their stats onto here */
struct ctp_module_message *ctp_stats_message = NULL, 
                          *ctp_stats_previous_message = NULL;

/* global format string */
char ctp_mbps_string[64];

/* per user stats. first is for current, second is for previous */
struct ctp_module_per_user_stats_data
{
    struct ctp_mod_rlc_seg_stats    *rlc_seg;
    struct ctp_mod_rlc_ras_stats    *rlc_ras;
    struct ctp_mod_iub_decap_stats  *iub_decap;
    struct ctp_mod_scheduler_stats  *scheduler;

} ctp_module_per_user_stats, ctp_module_prev_per_user_stats;

/* start index of config/user to print */
static int ctp_user_stats_start_index = 0;
static int ctp_config_start_index = 0;

/* number of lines written to ui */
static unsigned int ctp_ui_lines_written;

/* input field */
static char ctp_input_field[256];
static unsigned int ctp_input_field_index;
static char *ctp_input_field_label;
static bool ctp_currently_inputting = false;

/* holds which users have errors */
static bool ctp_users_with_errors[CTP_CONFIG_MAX_USERS];

/* statistics listener socket */
static int ctp_stat_socket = -1;

/* statistics clients */
static int ctp_stat_clients[1];

/* 
 * types
 */ 

/* which section is currently selected to be modified (switch using 'tab') */
enum
{
    ctp_css_config = 0,
    ctp_css_users,

    /* must be last */
    ctp_css_max

} ctp_current_selected_section = ctp_css_users;

/* statistics header */
struct ctp_stats_header
{
    unsigned int magic_number;
    unsigned int version;
    unsigned int size;

} __attribute((packed));

/* 
 * Forward declarations
 */ 

/* forward declarations */
void ctp_on_statistics_timer(int sig);
void ctp_refresh_screen();
void ctp_print_module_per_user_statistics();
void ctp_shutdown_stat_listener();

#endif /* __CTP_PRV_H_ */

