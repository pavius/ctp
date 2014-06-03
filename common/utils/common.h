/* 
 * Common utilities
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __COMMON_H_
#define __COMMON_H_

#include <time.h>
#include "common/utils/errors.h"

/* handle type */
typedef void* handle_t;

/* get min/max of two values */
#define get_maximum(x, y) ((x) > (y) ? (x) : (y))
#define get_minimum(x, y) ((x) < (y) ? (x) : (y))

/* array size */
#define array_size(array) (sizeof(array) / sizeof(array[0]))

#endif /* __RLC_COMMON_H_ */
