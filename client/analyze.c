#include <pcap.h>
#include <stdbool.h>

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
    struct sniff_ip* ip;
    unsigned int size_ip;
    bool df;

    vprint("Starting analysis\n");

    ip = (struct sniff_ip*) (pcap_packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
        fprintf(stderr, "ERROR: Invalid IP header length: %u bytes!\n", size_ip);
        return NULL;
    }

    df = packet_is_dont_fragment(ip);
    vprint("Packet is DF? %d\n", df);

    return result;
}
