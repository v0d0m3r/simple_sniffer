/*----------------------------------------------------------------------------*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <string.h>

/*----------------------------------------------------------------------------*/

#include <pcap.h>
#include <signal.h>
#include <limits.h>

/*----------------------------------------------------------------------------*/
/* Inner headers */
#include "Settings.h"
#include "Snif_lib.h"

/*----------------------------------------------------------------------------*/

pcap_t* open_interface(const Settings*const sets, char* ebuf)
{
    pcap_t* pc = pcap_create(sets->device, ebuf);
    if (pc == NULL) {
        /*
         * If this failed with "No such device", that means
         * the interface doesn't exist; return NULL, so that
         * the caller can see whether the device name is
         * actually an interface index.
         */
        if (strstr(ebuf, "No such device") != NULL)
            return (NULL);
        merror("%s", ebuf);
    }

    int status = pcap_set_promisc(pc, !sets->pflag);
    if (status != 0)
        merror("%s: Can't set promiscuous mode: %s",
               sets->device, pcap_statustostr(status));

    status = pcap_set_timeout(pc, 1000);
    if (status != 0)
        merror("%s: pcap_set_timeout failed: %s",
               sets->device, pcap_statustostr(status));

    char* cp;
    status = pcap_activate(pc);
    if (status < 0) {
        /*
         * pcap_activate() failed.
         */
        cp = pcap_geterr(pc);
        if (status == PCAP_ERROR)
            merror("%s", cp);
        else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
            /*
             * Return an error for our caller to handle.
             */
            snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n(%s)",
                     sets->device, pcap_statustostr(status), cp);
            pcap_close(pc);
            return (NULL);
        }
        else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0')
            merror("%s: %s\n(%s)", sets->device, pcap_statustostr(status), cp);
        else
            merror("%s: %s", sets->device, pcap_statustostr(status));
    } else if (status > 0) {
        /*
         * pcap_activate() succeeded, but it's warning us
         * of a problem it had.
         */
        cp = pcap_geterr(pc);
        if (status == PCAP_WARNING)
            mwarning("%s", cp);
        else if (status == PCAP_WARNING_PROMISC_NOTSUP &&
                 *cp != '\0')
            mwarning("%s: %s\n(%s)", sets->device, pcap_statustostr(status), cp);
        else
            mwarning("%s: %s", sets->device, pcap_statustostr(status));
    }
    return (pc);
}

/*----------------------------------------------------------------------------*/

int main(int argc, char** argv)
{
    Settings sets = {NULL, 0, NULL, 1};
    char ebuf[PCAP_ERRBUF_SIZE];
    load_settings(argc, argv, &sets, ebuf);

    pcap_t* pd = open_interface(&sets, ebuf);
    if (pd == NULL)
        merror("%s", ebuf);
    if (setgid(getgid()) != 0 || setuid(getuid()) != 0)
        fprintf(stderr, "Warning: setgid/setuid failed !\n");

    bpf_u_int32 localnet = 0, netmask = 0;
    struct bpf_program fcode;
    int Oflag = 1;			/* run filter code optimizer */
    if (pcap_compile(pd, &fcode, sets.filter, Oflag, netmask) < 0)
        merror("%s", pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
        merror("%s", pcap_geterr(pd));

    int dlt = pcap_datalink(pd);

    cleanup_settings(&sets);
}

/*----------------------------------------------------------------------------*/
