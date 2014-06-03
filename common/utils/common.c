/* 
 * Common utilities
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common/utils/common_prv.h"
#include "common/utils/assert.h"

/* safe string copy */
void safe_strncpy(char *dest, const char *src, const unsigned int size)
{
    /* do strncpy */
    strncpy(dest, src, size);

    /* always terminate */ 
    dest[size - 1] = 0;
}

/* caculate the ip cheecksum */
unsigned short ip_chksum_calculate(unsigned short *buffer, unsigned int word_count)
{
    unsigned long sum;

    /* calculate the checksoum */
    for (sum = 0; word_count > 0; word_count--)
    {
        sum += *buffer++;
        sum = (sum >> 16) + (sum & 0xffff);
    }

    // return the one's complement of sum
    return (unsigned short)(~sum);
}

/* string to uint */
rv_t str_to_uint(const char *number, unsigned int *value)
{
    char *end_of_number = (char *)number;

    /* try to convert */
    *value = strtol(number, &end_of_number, 10);

    /* return if parsed ok */
    if (*value == 0 && number == end_of_number)
    {
        /* error */
        return RV_ERR_PARSE;
    }
    else return RV_OK;
}

/* ip address to string */
const char* ip_addr_to_str(const unsigned int ip_addr, 
                           char *buffer, 
                           const unsigned int buffer_size)
{
    /* make sure there's enough room in the buffer */
    ctp_assert(buffer_size >= 17, "Need at least 17 bytes for IP address string");

    /* do the convert */
    snprintf(buffer, buffer_size, "%d.%d.%d.%d", (ip_addr >> 24) & 0xFF,
                                                 (ip_addr >> 16) & 0xFF,
                                                 (ip_addr >> 8) & 0xFF,
                                                 (ip_addr >> 0) & 0xFF);

    /* return teh buffer */
    return buffer;
}

/* increment an ip address */
unsigned int ip_addr_increment(const unsigned int ip_address, const unsigned int increment)
{
    /* just return the value teh requested increment */
    return (ip_address + increment);
}

/* convert hex string to byte array */
rv_t hex_str_to_byte_array(const char *hex_string, 
                           unsigned char *byte_array, 
                           const unsigned int max_byte_array_size,
                           unsigned int *byte_array_size)
{
    unsigned int hex_string_length;
    const char *current_pos_str;
    char *end_valid;
    unsigned char *current_pos_array;
    char hex_byte_string[3];

    /* get length of input */
    hex_string_length = strlen(hex_string);

    /* make sure it's an even number of characters and that there's enough room in the
       output buffer */
    if ((hex_string_length & 0x1) || (hex_string_length > (max_byte_array_size >> 1)))
    {
        /* invalid input */
        return RV_ERR_PARSE;
    }

    /* init hex string */
    bzero(hex_byte_string, sizeof(hex_byte_string));

    /* start converting the bytes */
    for (current_pos_str = hex_string, current_pos_array = byte_array; 
         *current_pos_str; 
         current_pos_str += 2)
    {
        /* copy to hex_byte_string */
        hex_byte_string[0] = current_pos_str[0];
        hex_byte_string[1] = current_pos_str[1];

        /* do the convert */
        *current_pos_array = strtol(hex_byte_string, &end_valid, 16);

        /* check if success */
        if (*current_pos_array == 0 && hex_byte_string == end_valid)
        {
            /* invalid input */
            return RV_ERR_PARSE;
        }

        /* next position */
        current_pos_array++;
    }

    /* set the bytes written */
    *byte_array_size = (current_pos_array - byte_array);

    /* success */
    return RV_OK;
}

/* convert hex string to byte array */
rv_t byte_array_to_hex_str(const unsigned char *byte_array, 
                           const unsigned int byte_array_size,
                           char *hex_string,
                           const unsigned int max_hex_string_size)
{
    unsigned int byte_index;
    const unsigned char *current_byte_array_pos;
    char *current_hex_string_pos;

    /* make sure there's enough room (+1 for null term) */
    if ((byte_array_size << 1) >= (max_hex_string_size + 1))
    {
        /* parse error */
        return RV_ERR_PARSE;
    }

    /* zero out the string so that null terms will be at the end */
    bzero(hex_string, max_hex_string_size);

    /* start converting */
    for (byte_index = 0, current_byte_array_pos = byte_array, current_hex_string_pos = hex_string; 
          byte_index < byte_array_size; 
          ++byte_index, current_hex_string_pos += 2, ++current_byte_array_pos)
    {
        /* convert string */
        snprintf(current_hex_string_pos, 3, "%02X", *current_byte_array_pos);
    }

    /* success */
    return RV_OK;
}

/* diff timespecs */
void timespec_diff(const struct timespec *start, 
                   const struct timespec *end, 
                   struct timespec *diff)
{
    if ((end->tv_nsec - start->tv_nsec) < 0) 
    {
        diff->tv_sec = end->tv_sec - start->tv_sec - 1;
        diff->tv_nsec = 1000000000 + end->tv_nsec - start->tv_nsec;
    } 
    else 
    {
        diff->tv_sec = end->tv_sec - start->tv_sec;
        diff->tv_nsec = end->tv_nsec - start->tv_nsec;
    }
}

/* compare two timespecs (positive means t1 > t2, 0 means they're equal and negative means t2 > t1 */
int timespec_compare(const struct timespec *t1,
                     const struct timespec *t2)
{
    /* do a simple compare */
    if (t1->tv_sec == t2->tv_sec) return (t1->tv_nsec - t2->tv_nsec);
    else                          return (t1->tv_sec - t2->tv_sec);
}

/* set dest to (source + nsec) */
void timespec_add_ns(const struct timespec *source, 
                     const unsigned int nsec,
                     struct timespec *dest)
{
    unsigned int nsec_left = nsec;

    /* set dest as source */
    *dest = *source;

    /* while there are full secodns (can be up to 4 so it's worth the loop) */
    while (nsec_left >= 1000000000)
    {
        /* add a second */
        dest->tv_sec++;

        /* decrement from nsec */
        nsec_left -= 1000000000;
    }

    /* add remainder nanoseconds */
    dest->tv_nsec += nsec_left;

    /* check overflow */
    if (dest->tv_nsec >= 1000000000)
    {
    	/* remove the second from nsec */
    	dest->tv_nsec -= 1000000000;

    	/* and add it to sec */
    	dest->tv_sec++;
    }
}
