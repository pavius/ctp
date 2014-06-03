/* 
 * assert module
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __CTP_ASSERT_H_
#define __CTP_ASSERT_H_

#include <stdio.h>
#include <stdlib.h>

/* assert handler */
extern void ctp_handle_assert(const char *descriptor);

/* assert with a string */
#define ctp_assert_str(condition, str)                                                          \
    do                                                                                          \
    {                                                                                           \
        if (!(condition))                                                                       \
        {                                                                                       \
            fflush(stdout);                                                                     \
            printf("\n\n");                                                                     \
            printf("Assertion Error @ %s:%d: %s\n\n", __FILE__, __LINE__, str);                 \
            ctp_handle_assert(str);                                                             \
        }                                                                                       \
    } while (0);

/* assert with format */
#define ctp_assert(condition, format, args...)                                                  \
    do                                                                                          \
    {                                                                                           \
        if (!(condition))                                                                       \
        {                                                                                       \
            char descriptor[512];                                                               \
            snprintf(descriptor, sizeof(descriptor), format, ## args);                          \
            ctp_assert_str(0, descriptor);                                                      \
        }                                                                                       \
    } while (0);

#endif /* __CTP_ASSERT_H_ */
