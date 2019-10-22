#ifndef SETTINGS_H
#define SETTINGS_H

/*----------------------------------------------------------------------------*/

#include <stdlib.h>

/*----------------------------------------------------------------------------*/
/* It represents settings from args cmd or json-c
 * After work has been finished we'll release resources
 * by cleanup_settings()
 * TODO:
 * add more options like filter optimization, snaplen,
 * count captured packets, etc.
*/
typedef struct {
    char* device;           /* Name of network interface, must be DLT_EN10MB  */
    int pflag;              /* Don't go promiscuous                           */
    char* filter;           /* Expression's syntax like tcpdump               */
    int is_clear_device;    /* Flag - Do we have to release device?           */
} Settings;

/*----------------------------------------------------------------------------*/
/* Release Settings's resource
 * Preconditions:  setts != NULL
 * Postconditions: none
*/
void cleanup_settings(Settings*const setts);

/*----------------------------------------------------------------------------*/
/* Handle args or json config, fill sets
 * Preconditions:  setts != NULL && argv != NULL && ebuf != NULL
 * Postconditions: sets->device != NULL
*/
void load_settings(int argc, char** argv, Settings* const sets, char* ebuf);

/*----------------------------------------------------------------------------*/

#endif // SETTINGS_H
