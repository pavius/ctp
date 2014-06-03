/* 
 * Error types
 * Void (c) 2011 
 *
 * Author: Eran Duchan
 * Written: June 15, 2011
 *
 */

#ifndef __ERRORS_H_
#define __ERRORS_H_

/* errors */
typedef enum rv_e
{
    RV_OK = 0,
    RV_ERR,
    RV_ERR_ALLOC, 
    RV_ERR_SOCKET,
    RV_ERR_CANT_CREATE,
    RV_ERR_CANT_OPEN,
    RV_ERR_PARSE,

} rv_t;

#endif /* __ERRORS_H_ */
