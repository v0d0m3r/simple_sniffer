/*----------------------------------------------------------------------------*/

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>

/*----------------------------------------------------------------------------*/

#include <pcap.h>

/*----------------------------------------------------------------------------*/
/* Inner headers */
#include "Settings.h"
#include "Snif_lib.h"

/*----------------------------------------------------------------------------*/

int simple_sniffer(const Settings* const sets, char* ebuf);

/*----------------------------------------------------------------------------*/

int main(int argc, char** argv)
{
    Settings sets = {NULL, 0, NULL, 1};
    char ebuf[PCAP_ERRBUF_SIZE];
    load_settings(argc, argv, &sets, ebuf);

    int status = simple_sniffer(&sets, ebuf);
    cleanup_settings(&sets);

    return status == -1 ? 1 : 0;
}

/*----------------------------------------------------------------------------*/

void print_tcp(bpf_u_int32 caplen, const u_char* packet,
               bpf_u_int32 shift)
{
    printf(" [TCP]");
    const bpf_u_int32 tcp_header_sz = 20;
    if (caplen < shift + tcp_header_sz) {
        mwarning("Invalid TCP header length: %u bytes\n", caplen - shift);
        return;
    }
    const struct tcphdr*const tcp = (const struct tcphdr*const)(packet + shift);
    printf("Src port: %d",   ntohs(tcp->th_sport));
    printf("\tDst port: %d", ntohs(tcp->th_dport));
}

/*----------------------------------------------------------------------------*/

void print_udp(bpf_u_int32 caplen, const u_char* packet,
               bpf_u_int32 shift)
{
    printf(" [UDP]");
    const bpf_u_int32 udp_header_sz = 8;
    if (caplen < shift + udp_header_sz) {
        mwarning("Invalid UDP header length: %u bytes\n",
                 caplen - shift);
        return;
    }
    const struct udphdr*const udp = (const struct udphdr*const)(packet + shift);
    printf("Src port: %d", ntohs(udp->uh_sport));
    printf("\tDst port: %d", ntohs(udp->uh_dport));
}

/*----------------------------------------------------------------------------*/

void print_ip4_info(bpf_u_int32 caplen, const u_char* packet,
                    bpf_u_int32 shift)
{
    const bpf_u_int32 ip4_header_sz = 20;
    if (caplen < shift + ip4_header_sz) {
        mwarning("Invalid IpV4 header length: %u bytes\n", caplen - shift);
        return;
    }

    const struct ip*const iph = (const struct ip*const)(packet + shift);
    printf("From: %s", inet_ntoa(iph->ip_src));
    printf("\t\tTo: %s", inet_ntoa(iph->ip_dst));

    switch(iph->ip_p) {
    case IPPROTO_TCP:
        print_tcp(caplen, packet, shift + ip4_header_sz);
        break;
    case IPPROTO_UDP:
        print_udp(caplen, packet, shift + ip4_header_sz);
        return;
    default:
        printf("[unknown #%d]", iph->ip_p);
        return;
    }
}

/*----------------------------------------------------------------------------*/

void print_ip6_info(bpf_u_int32 caplen, const u_char* packet,
                    bpf_u_int32 shift)
{
    const bpf_u_int32 ip6_header_sz = 40;
    if (caplen < shift + ip6_header_sz) {
        mwarning("Invalid IpV6 header length: %u bytes\n", caplen - shift);
        return;
    }
    const struct ip6_hdr*const
            ip6 = (const struct ip6_hdr*const)(packet + shift);

#define MAXSTR 129
    char str[MAXSTR];
    memset(str, 0, sizeof(char)*MAXSTR);
    inet_ntop(AF_INET6, &ip6->ip6_src, str, MAXSTR);
    printf("From: %s", str);

    inet_ntop(AF_INET6, &ip6->ip6_dst, str, MAXSTR);
    printf("\tTo: %s", str);
#undef MAXSTR
    uint64_t nexthdr = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    switch(nexthdr) {
    case IPPROTO_TCP:
        print_tcp(caplen, packet, shift + ip6_header_sz);
        break;
    case IPPROTO_UDP:
        print_udp(caplen, packet, shift + ip6_header_sz);
        return;
    default:
        printf("[unknown #%lu]", nexthdr);
        return;
    }
}

/*----------------------------------------------------------------------------*/

void got_packet(u_char* args, const struct pcap_pkthdr* header,
                const u_char* packet)
{
    (void)args;

    static int count = 1;                   /* packet counter */
    printf("\nN %d:", count);
    ++count;

    bpf_u_int32 ether_sz = 14;
    bpf_u_int32 caplen = header->caplen;
    if (caplen < ether_sz) {
        mwarning("Invalid Ether header length: %u bytes\n", caplen);
        return;
    }

    const struct ether_header* ethernet = (const struct ether_header*)(packet);
    const unsigned char*const
            ch = (const unsigned char*const)&ethernet->ether_type;
    int packet_type = (ch[0] << 8) + ch[1];
    switch (packet_type) {
    case ETH_P_IP:
        printf("[IPV4]");
        print_ip4_info(caplen, packet, ether_sz);
        break;
    case ETH_P_IPV6:
        printf("[IPV6]");
        print_ip6_info(caplen, packet, ether_sz);
        break;
    default:
        printf("[unknown #%d]", packet_type);
        break;
    }
    printf("\t%lf kbytes", header->len/1024.00);
}

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

int simple_sniffer(const Settings* const sets, char* ebuf)
{
    pcap_t* pd = open_interface(sets, ebuf);
    if (pd == NULL)
        merror("%s", ebuf);

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(pd) != DLT_EN10MB)
        merror("%s is not an Ethernet\n", sets->device);

    bpf_u_int32 localnet, netmask;
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(sets->device, &localnet, &netmask, ebuf) == -1) {
        mwarning("Couldn't get netmask for device %s: %s\n", sets->device, ebuf);
        localnet = 0;
        netmask = 0;
    }

    printf("Device: %s\n", sets->device);
    printf("Filter expression: %s\n", sets->filter);

    struct bpf_program fcode;
    int opt_flag = 1;			/* run filter code optimizer */
    if (pcap_compile(pd, &fcode, sets->filter, opt_flag, netmask) < 0)
        merror("%s", pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
        merror("%s", pcap_geterr(pd));

    int status = pcap_loop(pd, 0, got_packet, NULL);
    if (status == -2)
        putchar('\n');

    (void)fflush(stdout);

    if (status == -1)
        (void)fprintf(stderr, "simple_sniffer: pcap_loop: %s\n",
                      pcap_geterr(pd));
    pcap_close(pd);
    pcap_freecode(&fcode);

    return status;
}

/*----------------------------------------------------------------------------*/

