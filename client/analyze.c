#include <pcap.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "webscan.h"
#include "analyze.h"
#include "sniff.h"

static bool packet_is_dont_fragment(struct sniff_ip* ip) {
    unsigned int offset;

    offset = ntohs(ip->ip_off);

    // There could be a chance we have an actual fragment here. Needs testing.
    return (offset & IP_DF);
}


struct webscan_result *webscan_analyze_packet(const u_char *pcap_packet,
        bool verbose) {

    struct webscan_result *result;
    struct sniff_ip *ip;
    struct sniff_tcp *tcp;
    unsigned int size_ip;
    int ttl, window;
    bool df;

    vprint("Starting analysis\n");

    // The magic is described here: http://www.tcpdump.org/pcap.htm
    ip = (struct sniff_ip*) (pcap_packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    // This one is pretty obvious. The TCP part starts right after the IP stuff.
    tcp = (struct sniff_tcp*) (pcap_packet + SIZE_ETHERNET + size_ip);
    ttl = ip->ip_ttl;
    window = ntohs(tcp->th_win);

    if (size_ip < 20) {
        fprintf(stderr, "ERROR: Invalid IP header length: %u bytes!\n", size_ip);
        return NULL;
    }

    df = packet_is_dont_fragment(ip);
    vprint("From:\t\t\t%s\n", inet_ntoa(ip->ip_src));
    vprint("TTL:\t\t\t%d\n", ttl);
    vprint("IP ID:\t\t\t%d\n", ntohs(ip->ip_id));
    vprint("Don't Fragment Bit:\t%d\n", df);
    vprint("Initial Window size:\t%d\n", window);

    return result;
}
