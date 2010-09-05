#ifndef __WEBSCAN__H
#define __WEBSCAN__H

#include <pcap.h>
#include <stdbool.h>

#define vprint(...) if (verbose) fprintf(stderr, __VA_ARGS__)

struct webscan_result {
};

const char *webscan_format(struct webscan_result* result);
struct webscan_result *webscan(pcap_t *handle,
        bpf_u_int32 net,
        bpf_u_int32 mask,
        char *target,
        bool verbose);

#endif
