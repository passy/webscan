#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>


static char* lookup_device_name(void) {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return dev;
}


int main(void) {
    char *dev;

    dev = lookup_device_name();
    printf("Device: %s\n", dev);
    return EXIT_SUCCESS;
}
