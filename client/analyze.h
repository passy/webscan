#ifndef __analyze__h
#define __analyze__h
struct webscan_result *webscan_analyze_packet(const u_char *pcap_packet,
        bool verbose);
#endif
