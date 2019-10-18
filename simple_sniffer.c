/*----------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>

/*----------------------------------------------------------------------------*/

#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

/*----------------------------------------------------------------------------*/

#define HAVE_PCAP_FINDALLDEVS 1

/*----------------------------------------------------------------------------*/

static const char*const short_options = "c:hi:p";

/*----------------------------------------------------------------------------*/

static const struct option longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "interface", required_argument, NULL, 'i' },
    { "config-file", required_argument, NULL, 'c' },
    { "no-promiscuous-mode", no_argument, NULL, 'p' },
    { NULL, 0, NULL, 0 }
};

/*----------------------------------------------------------------------------*/

void print_usage()
{

}

/*----------------------------------------------------------------------------*/

static void error(const char* fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "simple_listener: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    exit(1);
}

/*----------------------------------------------------------------------------*/

typedef struct {
    const char* device;
    int pflag;  /* don't go promiscuous */
    int is_used_config;
} Settings;

/*----------------------------------------------------------------------------*/

void handle_options(Settings*const set, int argc, char** argv);

/*----------------------------------------------------------------------------*/

char* get_device_from_pcap(char* ebuf)
{
    pcap_if_t* devlist;

    /*
     * No interface was specified.  Pick one.
     */
#ifdef HAVE_PCAP_FINDALLDEVS
    /*
     * Find the list of interfaces, and pick
     * the first interface.
     */
    if (pcap_findalldevs(&devlist, ebuf) == -1)
        error("%s", ebuf);
    if (devlist == NULL)
        error("no interfaces available for capture");
    char* device = strdup(devlist->name);
    pcap_freealldevs(devlist);
#else /* HAVE_PCAP_FINDALLDEVS */
    /*
     * Use whatever interface pcap_lookupdev()
     * chooses.
     */
    device = pcap_lookupdev(ebuf);
    if (device == NULL)
        error("%s", ebuf);
#endif
    return device;
}

/*----------------------------------------------------------------------------*/

int main(int argc, char** argv)
{
    Settings sets = {NULL, 0, 0};
    if (argc)
        handle_options(&sets, argc, argv);

    char ebuf[PCAP_ERRBUF_SIZE];
    if (sets.device == NULL)
        sets.device = get_device_from_pcap(ebuf);
}

/*----------------------------------------------------------------------------*/

void handle_options(Settings* const sets, int argc, char** argv)
{
    assert(sets!=NULL && "message");
    int op = 0;    
    while (
        (op = getopt_long(argc, argv, short_options, longopts, NULL)) != -1)
        switch (op) {
        case 'c':
            ++(sets->is_used_config);
            break;
        case 'h':
            print_usage();
            exit(0);
        case 'i':
            sets->device = optarg;
            break;
        case 'p':
            ++(sets->pflag);
            break;
        }
}

/*----------------------------------------------------------------------------*/
