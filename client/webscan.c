#include "webscan.h"
#define vprint(...) if (verbose) fprintf(stderr, __VA_ARGS__)


const char *webscan_format(struct webscan_result *result) {
    (void)result;

    return "";
}


struct webscan_result *webscan(pcap_t *handle, char *target, bool verbose) {
    struct webscan_result *result;

    (void)handle;
    (void)target;

    vprint("Starting scan against %s.", target);

    return result;
}
