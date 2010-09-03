#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pcap.h>

#include "options.h"


struct ws_options {
    bool verbose;
    char hostname[WEBSCAN_TARGET_LENGTH];
};


static char* lookup_device_name(void) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return dev;
}

/**
 * Drop all privileges but CAP_NET_RAW, so we run in safe user space but can do
 * the network magic.
 */
static void drop_privileges(void) {
    cap_t caps;
    // List of caps we need after the uid/gid changed.
    cap_value_t cap_list[] = {
        CAP_NET_RAW
    };


    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "Cannot set capibilities to be kept!\n");
        exit(EXIT_FAILURE);
    }

    if (setegid(WEBSCAN_GROUP_ID) == -1 || seteuid(WEBSCAN_USER_ID) == -1) {
        perror("Dropping privileges failed");
        exit(EXIT_FAILURE);
    }

    caps = cap_get_proc();
    if (caps == NULL) {
        fprintf(stderr, "Cannot get current capibilities!\n");
        exit(EXIT_FAILURE);
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_list, CAP_SET) == -1) {
        fprintf(stderr, "Dropping privileges failed!\n");
        goto cleanup;
    }

    if (cap_set_proc(caps) == -1) {
        fprintf(stderr, "Applying capibilities failed!\n");
    }

cleanup:
    cap_free(caps);
}


static void print_usage(const char *prog_name) {
    printf("OVERVIEW: %s [OPTIONS] TARGET\n\n", prog_name);
    printf("OPTIONS:\n" \
           "-v\tTurn on verbose mode.\n"
           "-h\tShow this help screen.\n");
}


static struct ws_options parse_args(int argc, char *argv[]) {
    char arg;
    struct ws_options options;

    while ((arg = getopt(argc, argv, "hv")) != -1) {
        switch (arg) {
            case 'v':
                options.verbose = true;
                break;
        }
    }

    // getopt increments optind
    if (optind >= argc) {
        fprintf(stderr, "ERROR: Expected TARGET to come after options!\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    strncpy(options.hostname, argv[optind], WEBSCAN_TARGET_LENGTH);
    if (options.hostname[WEBSCAN_TARGET_LENGTH - 1] != '\0') {
        fprintf(stderr, "ERROR: Hostname is too long, sorry. I suck at "
                " C programming.\n");
        exit(EXIT_FAILURE);
    }

    return options;
}


int main(int argc, char *argv[]) {
    char *dev;
    struct ws_options options;

    // First action: get loose
    drop_privileges();
    options = parse_args(argc, argv);

    fprintf(stderr, "Running against target \"%s\".\n", options.hostname);
    dev = lookup_device_name();
    if (options.verbose) {
        fprintf(stderr, "Using device %s\n", dev);
    }
    return EXIT_SUCCESS;
}
