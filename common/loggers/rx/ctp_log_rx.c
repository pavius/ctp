/* 
 * Rx logger utility
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: July 25, 2011
 *
 */

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "common/loggers/rx/ctp_log_rx_prv.h"
#include "common/utils/assert.h"

/* get logger file name. TODO: move to common */
void ctp_log_get_log_file_name(const char *log_type_name,
                               char *filename,
                               const unsigned int filename_size)
{
    time_t now;
    struct tm now_info;
    struct stat st;

    /* get now */
    now = time(NULL);

    /* get now info */
    localtime_r(&now, &now_info);

    /* check if log dir exists */
    if (stat("logs", &st) != 0)
    {
    	/* make the dir */
    	ctp_assert(system("mkdir logs") != -1, "Failed to call mkdir");

    	/* now it must exist */
    	ctp_assert(stat("logs", &st) == 0, "Failed to create logs dir");
    }

    /* file name */
    snprintf(filename, filename_size,
             "logs/%02d%02d%04d-%02d%02d%02d-%s",
             now_info.tm_mday, now_info.tm_mon + 1, 1900 + now_info.tm_year,
             now_info.tm_hour, now_info.tm_min, now_info.tm_sec,
             log_type_name);

    /* terminate */
    filename[filename_size - 1] = '\0';
}

/* open the error file */
rv_t ctp_log_rx_open_files()
{
    char filename[512], text_filename[512], pcap_filename[512];

    /* get file name */
    ctp_log_get_log_file_name("rx-err", filename, sizeof(filename));

    /* add extensions */
    snprintf(text_filename, sizeof(text_filename) - 1, "%s.log", filename);
    snprintf(pcap_filename, sizeof(pcap_filename) - 1, "%s.pcap", filename);

    /* try to open the file */
    ctp_log_rx_file = fopen(text_filename, "w+");
    ctp_pcap_rx_file = fopen(pcap_filename, "w+");

    /* check if succeeded */
    if (ctp_log_rx_file == NULL || ctp_pcap_rx_file == NULL)
    {
        /* return error */
        return RV_ERR_CANT_OPEN;
    }

    /* initialize pcap header */
    struct
    {
        unsigned int    magic_number;   /* magic number */
        unsigned short  version_major;  /* major version number */
        unsigned short  version_minor;  /* minor version number */
        int             thiszone;       /* GMT to local correction */
        unsigned int    sigfigs;        /* accuracy of timestamps */
        unsigned int    snaplen;        /* max length of captured packets, in octets */
        unsigned int    network;        /* data link type */

    } __attribute((packed)) pcap_header = 
    {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 2,
        .sigfigs = 0,
        .snaplen = 2048,
        .network = 1
    };

    /* write to pcap file */
    ctp_assert(fwrite(&pcap_header, sizeof(pcap_header), 1, ctp_pcap_rx_file) == 1, 
               "Failed to output to pcap log");

    /* done */
    return RV_OK;
}

/* initialize rx logger */
rv_t ctp_log_rx_init(const unsigned int scheme)
{
    /* set the scheme */
    ctp_log_rx_scheme = scheme;

    /* nullify log file */
    ctp_log_rx_file = NULL;
    ctp_pcap_rx_file = NULL;

    /* create semaphore */
    ctp_assert(sem_init(&ctp_log_sem, 0, 1) == 0, "Failed to create semaphore");

    /* done */
    return RV_OK;
}

/* output to pcap file  */
rv_t ctp_log_rx_write_to_pcap_file(struct ctp_module_message *message,
                                   const struct tm *now_info,
                                   const struct timeval *now_usec,
                                   const char *error_string)
{
    /* get size */
    const unsigned int message_size = (message->header.tail_of_written_data - message->data);

    /* init pcap header for message */
    struct 
    {
        unsigned int ts_sec;         /* timestamp seconds */
        unsigned int ts_usec;        /* timestamp microseconds */
        unsigned int incl_len;       /* number of octets of packet saved in file */
        unsigned int orig_len;       /* actual length of packet */

    } __attribute((packed)) pcap_packet_header = 
    {
        .ts_sec = mktime((struct tm *)now_info),
        .ts_usec = now_usec->tv_usec,
        .incl_len = message_size,
        .orig_len = message_size
    };

    /* write header and payload */
    ctp_assert(fwrite(&pcap_packet_header, sizeof(pcap_packet_header), 1, ctp_pcap_rx_file) == 1 && 
               fwrite(message->data, message_size, 1, ctp_pcap_rx_file) == 1,
               "Failed to output to pcap log");

    /* flush it */
    fflush(ctp_log_rx_file);
}

/* output to text file */
rv_t ctp_log_rx_write_to_text_file(struct ctp_module_message *message,
                                   const struct tm *now_info,
                                   const struct timeval *now_usec,
                                   const char *error_string)
{
    unsigned int byte_idx;
    unsigned char *current_byte;

    /* shove to file */
    ctp_assert(fprintf(ctp_log_rx_file, "[%02d:%02d:%02d.%03d %02d/%02d/%02d] %s:\n", 
                       now_info->tm_hour, now_info->tm_min, now_info->tm_sec, (int)(now_usec->tv_usec / 1000),
                       now_info->tm_mday, now_info->tm_mon + 1, 1900 + now_info->tm_year,
                       error_string) >= 0, "Failed to output to Rx log");
    
    /* print payload */
    for (current_byte = message->data, byte_idx = 0; 
         current_byte < message->header.tail_of_written_data; 
         ++current_byte)
    {
        /* print byte */
        ctp_assert(fprintf(ctp_log_rx_file, "%02X", *current_byte) >= 0, 
                   "Failed to output to Rx log");
    
        /* row */
        if (byte_idx >= 40)
        {
            /* space out */
            ctp_assert(fprintf(ctp_log_rx_file, "\n") >= 0, "Failed to output to Rx log");
    
            /* zero out index */
            byte_idx = 0;
        }
        else ++byte_idx;
    }
    
    /* space out */
    ctp_assert(fprintf(ctp_log_rx_file, "\n\n") >= 0, "Failed to output to Rx log");

    /* flush the file */
    fflush(ctp_log_rx_file);

    /* done */
    return RV_OK;
}

/* handle events */
rv_t ctp_log_rx_event(struct ctp_module_message *message,
                      const char *format, ...)
{
    va_list arg_list;
    char error_string[256];

    /* prepare arg list */
    va_start(arg_list, format);

    /* format arglist */
    vsnprintf(error_string, sizeof(error_string), format, arg_list);
    error_string[sizeof(error_string) - 1] = '\0';

    /* end args */
    va_end(arg_list);

    /* do we need to log? */
    if (ctp_log_rx_scheme & CTP_LOG_RX_SCHEME_LOG)
    {
        struct timeval now;
        struct tm now_info;

        /* do we need to open an error file? this will happen if no errors have been logged
         * yet.
         */
        if (ctp_log_rx_file == NULL || ctp_pcap_rx_file == NULL)
        {
            /* try to open the file */
            ctp_assert(ctp_log_rx_open_files() == RV_OK, "Failed to create error file");
        }

        /* get now */
        gettimeofday(&now, NULL);

        /* get now info */
        localtime_r(&now.tv_sec, &now_info);

        /* sync */
        sem_wait(&ctp_log_sem);

        /* output to files */
        ctp_log_rx_write_to_text_file(message, &now_info, &now, error_string);
        ctp_log_rx_write_to_pcap_file(message, &now_info, &now, error_string);

        /* sync */
        sem_post(&ctp_log_sem);
    }

    /* do we need to assert? */
    if (ctp_log_rx_scheme & CTP_LOG_RX_SCHEME_ASSERT)
    {
        /* simply assert */
        ctp_assert_str(false, error_string);
    }

    /* done */
    return RV_OK;
}

/* shutdown rx logger */
rv_t ctp_log_rx_shutdown()
{
    /* sync and never release */
    if (ctp_log_rx_file != NULL || ctp_pcap_rx_file != NULL)
        sem_wait(&ctp_log_sem);

    /* is the log file open? */
    if (ctp_log_rx_file != NULL)
    {
        /* close the file */
        fflush(ctp_log_rx_file);
        fclose(ctp_log_rx_file);
    }

    /* is the log file open? */
    if (ctp_pcap_rx_file != NULL)
    {
        /* close the file */
        fflush(ctp_pcap_rx_file);
        fclose(ctp_pcap_rx_file);
    }

    /* done */
    return RV_OK;
}

