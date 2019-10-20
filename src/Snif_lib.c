/*----------------------------------------------------------------------------*/

#include "Snif_lib.h"

/*----------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/*----------------------------------------------------------------------------*/

void merror(const char* fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "simple_sniffer: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    exit(S_ERR_HOST_PROGRAM);
}

/*----------------------------------------------------------------------------*/

void mwarning(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "simple_sniffer: : WARNING: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
}

/*----------------------------------------------------------------------------*/
