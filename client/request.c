#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "request.h"

int make_request_socket(int port) {
    int socket_desc;
    struct sockaddr_in local_addr;
    int opt = 1;

    // XXX: Is a bzero necessary?
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(port);

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        goto failure;
    }
    // Make sure we don't have to wait for 60 seconds between two runs.
    // This could also be avoided by using randomized or sequential local port
    // numbers, but this increases complexity massively because we have to keep
    // track of the local port for the later filtering.
    // By the way, the zombie socket is created when we start the connect() but
    // don't receive an ACK. So, at some point in the future, this could become
    // obsolete.
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(socket_desc, (struct sockaddr *) &local_addr,
                sizeof(local_addr)) != 0) {

        // Close the fd before!
        close(socket_desc);
        socket_desc = -1;
        goto failure;
    }

    goto success;

failure:
    perror("ERROR: Failed on binding socket");

success:
    return socket_desc;
}

int open_connection(char *hostname, int remote_port, int socket_desc) {
    struct sockaddr_in server;
    struct hostent *host;

    host = gethostbyname(hostname);
    if (host == NULL) {
        fprintf(stderr, "Failed to resolve hostname %s!", hostname);
        return -1;
    }

    server.sin_family = host->h_addrtype;
    // XXX: What happens without that first cast?
    memcpy((char *) &server.sin_addr.s_addr, host->h_addr_list[0],
            host->h_length);
    server.sin_port = htons(remote_port);

    if (connect(socket_desc, (struct sockaddr *) &server,
                sizeof(server)) == -1) {
        perror("Error while connecting to target host");
        socket_desc = -1;
    }

    return socket_desc;
}

int close_connection(int socket_desc) {
    if (close(socket_desc) == -1) {
        perror("Error while closing socket");
        return -1;
    }
    return 0;
}
