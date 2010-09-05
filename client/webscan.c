#include <stdlib.h>
#include <time.h>
#include "webscan.h"
#include "request.h"
#include "analyze.h"


void webscan_print(struct webscan_result *result) {
    struct tm *ts;
    char uptime[80];

    ts = localtime(&result->uptime);
    strftime(uptime, sizeof(uptime), "%a %Y-%m-%d %H:%M:%S %Z", ts);

    printf("Uptime:\t%s\n", uptime);
}


void make_filter(pcap_t *handle, char *target,
        int local_port, int remote_port, bpf_u_int32 net) {
    // The 120 is copied. I have to check our where it comes from.
    char filter_app[120];
    struct bpf_program filter;

    snprintf(filter_app, sizeof(filter_app),
            "tcp and src host %s and dst port %d and src port %d",
            target, local_port, remote_port);

    if (pcap_compile(handle, &filter, filter_app, 0, net) == -1) {
        pcap_perror(handle, "Error while compiling filter app");
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        pcap_perror(handle, "Setting filter failed");
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&filter);
}

/**
 * Opens and closes the tcp connection.
 * Exits the program if something went wrong.
 */
void webscan_request(char *target, int local_port, int remote_port) {
    int socket_desc;

    socket_desc = make_request_socket(local_port);
    if (socket_desc == -1) {
        exit(EXIT_FAILURE);
    }

    // Overwriting. There does not happen anything to the descriptor other than
    // error handling.
    socket_desc = open_connection(target, remote_port, socket_desc);
    if (socket_desc == -1) {
        exit(EXIT_FAILURE);
    }
    // Later, we probably want to get some more information like HTTP Server and
    // stuff.
    if (close_connection(socket_desc) == -1) {
        exit(EXIT_FAILURE);
    }
}

struct webscan_result *webscan(pcap_t *handle, bpf_u_int32 net,
        bpf_u_int32 mask, char *target, bool verbose) {

    int local_port;
    int remote_port;
    const u_char *pcap_packet;
    struct pcap_pkthdr pcap_header;

    vprint("Starting scan against %s\n", target);
    vprint("Using network %x with netmask %x\n", net, mask);
    // Get a local port.
    // I guess there's a way to dynamically get a free port. This is kind of
    // lame. Other examples I've seen do actually use some random number
    // generator what I think is even worse.
    local_port = 4024;
    // This should be configurable as well. At least HTTPS/443 should be
    // supported.
    remote_port = 80;
    vprint("Using local port %d\n", local_port);
    vprint("Using remote port %d\n", remote_port);

    make_filter(handle, target, local_port, remote_port, net);
    webscan_request(target, local_port, remote_port);
    vprint("Starting packet capturing\n");

    do {
        pcap_packet = pcap_next(handle, &pcap_header);
    } while (pcap_packet == NULL);

    return webscan_analyze_packet(pcap_packet, verbose);
}

void webscan_free_result(struct webscan_result *result) {
    free(result);
}
