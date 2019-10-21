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
#include <net/ethernet.h>
#include <netinet/ip.h>

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

void print_ip4_info(const struct ip* ip_head)
{
}

void print_ip6_info()
{

}

void got_packet(u_char* args, const struct pcap_pkthdr* header,
                const u_char* packet)
{
    static int count = 1;                   /* packet counter */
    printf("\nPacket number %d:\n", count);
    ++count;

    int ether_sz = 14;
    if (header->caplen < ether_sz) {
        mwarning("   * Invalid Ether header length: %u bytes\n", header->caplen);
        return;
    }

    const struct ether_header* ethernet = (const struct ether_header*)(packet);;

    const int ip4_header_sz = 20;
    const int ip4_header_sz = 40;
    int ip_shift = 0;
    unsigned char* ch = (unsigned char*)&ethernet->ether_type;
    int packet_type = (ch[0] << 8) + ch[1];
    switch (packet_type) {
    case ETH_P_IP:
        if (header->caplen < ether_sz + ip4_header_sz) {
            mwarning("   * Invalid IpV4 header length: %u bytes\n",
                     header->caplen - ether_sz);
            return;
        }
        printf("   Protocol: IPV4\n");
        break;
    case ETH_P_IPV6:
        if (header->caplen < ether_sz + ip4_header_sz) {
            mwarning("   * Invalid IpV6 header length: %u bytes\n",
                     header->caplen - ether_sz);
            return;

        }
        printf("   Protocol: IPV6\n");
        break;
    default:
        printf("   Protocol: unknown #%d\n", packet_type);
        return;
    }



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

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(pd) != DLT_EN10MB)
        merror("%s is not an Ethernet\n", sets.device);

    bpf_u_int32 localnet, netmask;
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(sets.device, &localnet, &netmask, ebuf) == -1) {
        mwarning("Couldn't get netmask for device %s: %s\n", sets.device, ebuf);
        localnet = 0;
        netmask = 0;
    }

    printf("Device: %s\n", sets.device);
    printf("Filter expression: %s\n", sets.filter);

    struct bpf_program fcode;
    int opt_flag = 1;			/* run filter code optimizer */
    if (pcap_compile(pd, &fcode, sets.filter, opt_flag, netmask) < 0)
        merror("%s", pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
        merror("%s", pcap_geterr(pd));

    int status = pcap_loop(pd, 0, got_packet, NULL);
    if (status == -2)
        putchar('\n');

    (void)fflush(stdout);

    if (status == -1)
        (void)fprintf(stderr, "%s: pcap_loop: %s\n",
            "simple_sniffer", pcap_geterr(pd));


    pcap_close(pd);
    pcap_freecode(&fcode);
    cleanup_settings(&sets);
    exit(status == -1 ? 1 : 0);
}

/*----------------------------------------------------------------------------*/
