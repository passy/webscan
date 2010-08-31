#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <stdbool.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pcap.h>

// I'm not sure where to define this.
#define DROP_USER_ID 1000
#define DROP_GROUP_ID 1000


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
    cap_value_t cap_list[] = {
        CAP_NET_RAW
    };


    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "Cannot set capibilities to be kept!\n");
        exit(EXIT_FAILURE);
    }

    if (setegid(DROP_GROUP_ID) == -1 || seteuid(DROP_USER_ID) == -1) {
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
    printf("OVERVIEW: %s\n\n", prog_name);
    printf("OPTIONS:\n" \
           "-v:\tTurn on verbose mode.\n"
           "-h:\tShow this help screen.\n");
}


int main(int argc, char *argv[]) {
    char *dev;
    char arg;
    bool verbose = false,
         run = false;

    // First action: get loose
    drop_privileges();

    while ((arg = getopt(argc, argv, "hv")) != -1) {
        switch (arg) {
            case 'v':
                verbose = true;
                break;
        }
    }

    if (run) {
        dev = lookup_device_name();
    } else {
        print_usage(argv[0]);
    }
    return EXIT_SUCCESS;
}
