#include <pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "webscan.h"
#include "analyze.h"
#include "sniff.h"


static bool packet_is_dont_fragment(const struct sniff_ip* ip) {
    unsigned int offset;

    offset = ntohs(ip->ip_off);

    // There could be a chance we have an actual fragment here. Needs testing.
    return (offset & IP_DF);
}


/**
 * Logic stolen from nmap and sprint.
 * Note to myself: Be sure to use GPL!
 */
int extract_timestamp_from_tcp(const struct sniff_tcp *tcp, time_t *timestamp) {

    const unsigned char *p;
    int len = 0;
    int op;
    int oplen;

    /* first we find where the tcp options start ... */
    p = ((const unsigned char *)tcp) + 20;
    len = 4 * tcp->th_offx2 - 20;
    while(len > 0 && *p != 0 /* TCPOPT_EOL */) {
        op = *p++;
        if (op == 0 /* TCPOPT_EOL */) break;
        if (op == 1 /* TCPOPT_NOP */) { len--; continue; }
        oplen = *p++;   
        if (oplen < 2) break; /* No infinite loops, please */
        if (oplen > len) break; /* Not enough space */
        if (op == 8 /* TCPOPT_TIMESTAMP */ && oplen == 10) {
            /* Legitimate ts option */
            if (timestamp) {
                memcpy((char *) timestamp, p, 4);
                *timestamp = ntohl(*timestamp);
            }
            return 1;
        }
        len -= oplen;
        p += oplen - 2;
    }

    /* Didn't find anything */
    if (timestamp) *timestamp = 0;
    return 0;
}


struct webscan_result *webscan_analyze_packet(const u_char *pcap_packet,
        bool verbose) {

    struct webscan_result *result = malloc(sizeof(struct webscan_result));
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    unsigned int size_ip;
    int ttl, window;
    time_t timestamp;
    bool df;

    vprint("Starting analysis\n");
    bzero(result, sizeof(struct webscan_result));

    // The magic is described here: http://www.tcpdump.org/pcap.htm
    ip = (const struct sniff_ip*) (pcap_packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    // This one is pretty obvious. The TCP part starts right after the IP stuff.
    tcp = (const struct sniff_tcp*) (pcap_packet + SIZE_ETHERNET + size_ip);
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

    if (extract_timestamp_from_tcp(tcp, &timestamp) == 1) {
        vprint("Raw Timestamp:\t\t%ld\n", timestamp);
        result->uptime = time(NULL) - (timestamp / 100);
    }

    return result;
}
