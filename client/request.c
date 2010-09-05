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

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(port);

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        goto failure;
    }

    if (bind(socket_desc, (struct sockaddr *) &local_addr,
                sizeof(local_addr)) != 0) {
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
