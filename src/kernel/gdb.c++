// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "gdb.h++"
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using namespace pos::kernel;

/*
 * gdbserver is a packet-oriented protocol, encoded as a stream of bytes (over
 * TCP for now).  The performance isn't important here, so we just glob the
 * whole packet into memory.
 */
class packet {
public:
    char _buf[4096];
    size_t _len;
    bool _valid;

public:
    packet(int fd)
    : _len(0),
      _valid(0)
    {
        int checksum_bytes = -1;
        ssize_t count;

        do {
            count = read(fd, _buf + _len, 1);
            if (count < 0)
                return;

            _len += count;

            if (checksum_bytes >= 0)
                checksum_bytes++;
            if (_buf[_len-1] == '#')
                checksum_bytes = 0;
            if (checksum_bytes == 2)
                break;
        } while (_len < sizeof(_buf));

        _valid = checksum_bytes == 2;
    }
};

void gdbserver::main(void)
{
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in socket_addr;
    memset(&socket_addr, 0, sizeof(socket_addr));
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    socket_addr.sin_port = htons(_port);

    int sockopt = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &sockopt, sizeof(sockopt));


    if (bind(socket_fd, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) != 0) {
        perror("unable to bind");
        abort();
    }

    if (listen(socket_fd, 1) != 0) {
        perror("unable to listen");
        abort();
    }

    struct sockaddr_in client_addr;
    socklen_t client_len;
    int client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("unable to accept");
        abort();
    }

    close(socket_fd);

    while (true) {
        auto req = packet(client_fd);
        if (!req._valid)
            break;
        write(client_fd, "+$#00", 1);
        fprintf(stderr, "req: %s\n", req._buf);
    }

    close(client_fd);
}
