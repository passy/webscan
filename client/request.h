#ifndef __REQUEST__H
#define __REQUEST__H

int make_request_socket(int port);
int open_connection(char *hostname, int remote_port, int socket_desc);
int close_connection(int socket_desc);

#endif
