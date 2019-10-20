#ifndef SETTINGS_H
#define SETTINGS_H

/*----------------------------------------------------------------------------*/

#include <stdlib.h>

/*----------------------------------------------------------------------------*/

typedef struct {
    char* device;    
    int pflag;  /* don't go promiscuous */
    char* filter;
    int is_clear_device;
} Settings;

/*----------------------------------------------------------------------------*/

void cleanup_settings(Settings* setts);

/*----------------------------------------------------------------------------*/

void load_settings(int argc, char** argv, Settings* const sets, char* ebuf);

/*----------------------------------------------------------------------------*/

#endif // SETTINGS_H
