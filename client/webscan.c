#include "webscan.h"
#define vprint(...) if (verbose) fprintf(stderr, __VA_ARGS__)

const char *webscan_format(struct webscan_result *result) {
    (void)result;

    return "";
}


char *make_filter_app(char *target, int local_port, int remote_port) {
    // The 120 is copied. I have to check our where it comes from.
    char filter_app[120];

    snprintf(filter_app, sizeof(filter_app),
            "tcp and src host %s and dst port %d and src port %d",
            target, local_port, remote_port);

    return "";
}


struct webscan_result *webscan(pcap_t *handle, bpf_u_int32 net,
        bpf_u_int32 mask, char *target, bool verbose) {

    int local_port;
    struct webscan_result *result;

    (void)handle;

    vprint("Starting scan against %s\n", target);
    vprint("Using network %x with netmask %x\n", net, mask);
    // Get a local port.
    // I guess there's a way to dynamically get a free port. This is kind of
    // lame. Other examples I've seen do actually use some random number
    // generator what I think is even worse.
    local_port = 4024;
    vprint("Using local port %d\n", local_port);

    return result;
}
