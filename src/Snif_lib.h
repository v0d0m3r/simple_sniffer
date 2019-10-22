#ifndef SNIF_LIB_H
#define SNIF_LIB_H

/*----------------------------------------------------------------------------*/

#include <stdlib.h>

/*----------------------------------------------------------------------------*/

typedef enum {
    S_SUCCESS           = 0,
    S_ERR_HOST_PROGRAM  = 1
} Status_exit_codes_t;

/*----------------------------------------------------------------------------*/
/* Tell us that's error was occured and quit
 * Preconditions:  fmt != NULL
 * Postconditions: none
 */
void merror(const char* fmt, ...);

/*----------------------------------------------------------------------------*/
/* Tell us that's warning was occured
 * Preconditions:  fmt != NULL
 * Postconditions: none
 */
void mwarning(const char *fmt, ...);

/*----------------------------------------------------------------------------*/

#endif // SNIF_LIB_H
