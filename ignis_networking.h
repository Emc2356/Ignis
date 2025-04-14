/*
 * Copyright (c) 2025 Stamelos Vasilis
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
#ifndef IGNIS__NETWORKING_H
#define IGNIS__NETWORKING_H

#include <stdlib.h>

#ifndef IG_NETWORKING_API
#define IG_NETWORKING_API
#endif /* IG_NETWORKING_API */

#ifndef IG_NETWORKING_MALLOC
#define IG_NETWORKING_MALLOC(size) malloc(size)
#define IG_NETWORKING_FREE(ptr) free(ptr)
#endif /* IG_NETWORKING_MALLOC */
#ifndef IG_NETWORKING_FREE
#error "IG_NETWORKING_FREE must be defined when IG_NETWORKING_MALLOC is defined"
#endif /* IG_NETWORKING_FREE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

IG_NETWORKING_API int IgNetworking_init(void);
IG_NETWORKING_API void IgNetworking_shutdown(void);

#define IG_IPV4_ADDRSTRLEN 16
#define IG_IPV6_ADDRSTRLEN 46
typedef enum IgIProtocol {
    IG_IPV4 = 0,
    IG_IPV6 = 1
} IgIProtocol;

/* TCP socket */
typedef struct IgTcpSocket IgTcpSocket;

/* server */
IG_NETWORKING_API IgTcpSocket* IgTcpSocket_listen(const char* hostname, int port, IgIProtocol protocol);
IG_NETWORKING_API IgTcpSocket* IgTcpSocket_accept(IgTcpSocket* server);

/* client */
IG_NETWORKING_API IgTcpSocket* IgTcpSocket_connect(const char* hostname, int port, IgIProtocol protocol);

/* server and client */
IG_NETWORKING_API void IgTcpSocket_close(IgTcpSocket* tcpsocket);
IG_NETWORKING_API int IgTcpSocket_read(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size);
IG_NETWORKING_API int IgTcpSocket_peek(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size);
IG_NETWORKING_API int IgTcpSocket_write(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size);
IG_NETWORKING_API int IgTcpSocket_read_entire_buffer(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size);
IG_NETWORKING_API int IgTcpSocket_write_entire_buffer(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size);

/* UDP socket */
typedef struct IgUdpSocket IgUdpSocket;

/* Server */
IG_NETWORKING_API IgUdpSocket* IgUdpSocket_bind(const char* hostname, int port, IgIProtocol protocol);

/* Client */
IG_NETWORKING_API IgUdpSocket* IgUdpSocket_create(IgIProtocol protocol);
IG_NETWORKING_API int IgUdpSocket_connect(IgUdpSocket* socket, const char* hostname, int port);

/* Both */
IG_NETWORKING_API void IgUdpSocket_close(IgUdpSocket* socket);
IG_NETWORKING_API int IgUdpSocket_recvfrom(
    IgUdpSocket* socket, 
    char* buffer, 
    size_t buffer_size,
    char* out_src_addr,  /* Optional: fills with sender IP */
    int* out_src_port    /* Optional: fills with sender port */
);
IG_NETWORKING_API int IgUdpSocket_sendto(
    IgUdpSocket* socket,
    const char* buffer,
    size_t buffer_size,
    const char* dest_addr,  /* NULL for connected sockets */
    int dest_port           /* Ignored if dest_addr is NULL */
);
IG_NETWORKING_API int IgUdpSocket_read(IgUdpSocket* socket, char* buffer, size_t buffer_size);
IG_NETWORKING_API int IgUdpSocket_write(IgUdpSocket* socket, const char* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IGNIS__NETWORKING_H */

#ifdef IG_NETWORKING_IMPLEMENTATION

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wswitch-default"
#pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif /* __clang__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else /* _WIN32 */
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <signal.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif /* _WIN32 */
#include <string.h>
#include <stdio.h>

struct IgTcpSocket {
    #ifdef _WIN32
        SOCKET fd;
        struct sockaddr_storage addr;
    #else /* _WIN32 */
        int fd;                       /* Socket file descriptor */
        /* not certain if this is information i want to keep or no */
        struct sockaddr_storage addr; /* Remote address (for accepted connections) */
    #endif /* _WIN32 */
};

struct IgUdpSocket {
    #ifdef _WIN32
        SOCKET fd;
        IgIProtocol protocol;
        BOOL is_connected;
        struct sockaddr_storage bound_addr;
    #else /* _WIN32 */
        int fd;
        IgIProtocol protocol;
        int is_connected;  /* For "connected" UDP mode */
        struct sockaddr_storage bound_addr;
    #endif /* _WIN32 */
};
    
#ifdef _WIN32
#define IG_NETWORKING_INTERNAL_CALL(func) func##_win32
#else /* _WIN32 */
#define IG_NETWORKING_INTERNAL_CALL(func) func##_posix
#endif /* _WIN32 */

#ifdef _WIN32

static int IgNetworking_is_winsock_initialized = 0;
static int IgNetworking_init_win32(void) {
    WSADATA wsaData;
        
    if (!IgNetworking_is_winsock_initialized) {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return 0;
        }
        IgNetworking_is_winsock_initialized = 1;
    }
    return 1;
}

static void IgNetworking_shutdown_win32(void) {
    if (IgNetworking_is_winsock_initialized) {
        WSACleanup();
        IgNetworking_is_winsock_initialized = 0;
    }
}

static int IgTcpSocket_resolve_address(const char* hostname, int port, IgIProtocol protocol, struct sockaddr_storage* addr) {
    ADDRINFOA hints, *res;
    char port_str[16];
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (protocol == IG_IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    sprintf(port_str, "%d", port);
    
    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        return 0;
    }
    
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 1;
}

static IgTcpSocket* IgTcpSocket_listen_win32(const char* hostname, int port, IgIProtocol protocol) {
    IgTcpSocket* sock;
    struct sockaddr_storage addr;
    BOOL opt = TRUE;
    
    sock = (IgTcpSocket*)IG_NETWORKING_MALLOC(sizeof(IgTcpSocket));
    if (!sock) return NULL;
    memset(sock, 0, sizeof(IgTcpSocket));
    
    sock->fd = socket((protocol == IG_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock->fd == INVALID_SOCKET) {
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    /* Set SO_REUSEADDR */
    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    /* Bind */
    if (!IgTcpSocket_resolve_address(hostname, port, protocol, &addr)) {
        closesocket(sock->fd);
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    if (bind(sock->fd, (struct sockaddr*)&addr, 
            (protocol == IG_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        closesocket(sock->fd);
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    /* Listen */
    if (listen(sock->fd, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock->fd);
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    return sock;
}

static IgTcpSocket* IgTcpSocket_accept_win32(IgTcpSocket* server) {
    IgTcpSocket* client;
    int addrlen;
    
    client = (IgTcpSocket*)IG_NETWORKING_MALLOC(sizeof(IgTcpSocket));
    if (!client) return NULL;
    memset(client, 0, sizeof(IgTcpSocket));
    
    addrlen = sizeof(client->addr);
    client->fd = accept(server->fd, (struct sockaddr*)&client->addr, &addrlen);
    
    if (client->fd == INVALID_SOCKET) {
        IG_NETWORKING_FREE(client);
        return NULL;
    }
    
    return client;
}

static IgTcpSocket* IgTcpSocket_connect_win32(const char* hostname, int port, IgIProtocol protocol) {
    IgTcpSocket* sock;
    struct sockaddr_storage addr;
    
    sock = (IgTcpSocket*)IG_NETWORKING_MALLOC(sizeof(IgTcpSocket));
    if (!sock) return NULL;
    memset(sock, 0, sizeof(IgTcpSocket));
    
    sock->fd = socket((protocol == IG_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock->fd == INVALID_SOCKET) {
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    /* Resolve address */
    if (!IgTcpSocket_resolve_address(hostname, port, protocol, &addr)) {
        closesocket(sock->fd);
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    /* Connect */
    if (connect(sock->fd, (struct sockaddr*)&addr, 
               (protocol == IG_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        closesocket(sock->fd);
        IG_NETWORKING_FREE(sock);
        return NULL;
    }
    
    return sock;
}

static void IgTcpSocket_close_win32(IgTcpSocket* tcpsocket) {
    if (tcpsocket->fd != INVALID_SOCKET) {
        shutdown(tcpsocket->fd, SD_BOTH);
        closesocket(tcpsocket->fd);
    }
    IG_NETWORKING_FREE(tcpsocket);
}

static int IgTcpSocket_read_win32(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    int bytes = recv(tcpsocket->fd, buffer, (int)buffer_size, 0);
    if (bytes == SOCKET_ERROR) return -1;
    return bytes;
}

static int IgTcpSocket_peek_win32(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    int bytes = recv(tcpsocket->fd, buffer, (int)buffer_size, MSG_PEEK);
    if (bytes == SOCKET_ERROR) return -1;
    return bytes;
}

static int IgTcpSocket_write_win32(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size) {
    int bytes = send(tcpsocket->fd, buffer, (int)buffer_size, 0);
    if (bytes == SOCKET_ERROR) return -1;
    return bytes;
}

static IgUdpSocket* IgUdpSocket_bind_win32(const char* hostname, int port, IgIProtocol protocol) {
    IgUdpSocket* udpsocket;
    struct sockaddr_storage addr;
    
    udpsocket = (IgUdpSocket*)IG_NETWORKING_MALLOC(sizeof(IgUdpSocket));
    if (!udpsocket) return NULL;
    memset(udpsocket, 0, sizeof(IgUdpSocket));

    udpsocket->fd = socket(protocol == IG_IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpsocket->fd == INVALID_SOCKET) {
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    
    if (protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((u_short)port);
        if (hostname) InetPtonA(AF_INET6, hostname, &addr6->sin6_addr);
        else addr6->sin6_addr = in6addr_any;
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((u_short)port);
        if (hostname) InetPtonA(AF_INET, hostname, &addr4->sin_addr);
        else addr4->sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(udpsocket->fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(udpsocket->fd);
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    udpsocket->protocol = protocol;
    memcpy(&udpsocket->bound_addr, &addr, sizeof(addr));
    return udpsocket;
}

static IgUdpSocket* IgUdpSocket_create_win32(IgIProtocol protocol) {
    IgUdpSocket* udpsocket;
    
    udpsocket = (IgUdpSocket*)IG_NETWORKING_MALLOC(sizeof(IgUdpSocket));
    if (!udpsocket) return NULL;
    memset(udpsocket, 0, sizeof(IgUdpSocket));

    udpsocket->fd = socket(protocol == IG_IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpsocket->fd == INVALID_SOCKET) {
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    udpsocket->protocol = protocol;
    return udpsocket;
}

static int IgUdpSocket_connect_win32(IgUdpSocket* udpsocket, const char* hostname, int port) {
    struct sockaddr_storage addr;
    if (udpsocket->is_connected) return 0;

    memset(&addr, 0, sizeof(addr));
    
    if (udpsocket->protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((u_short)port);
        InetPtonA(AF_INET6, hostname, &addr6->sin6_addr);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((u_short)port);
        InetPtonA(AF_INET, hostname, &addr4->sin_addr);
    }

    if (connect(udpsocket->fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        return 0;
    }

    udpsocket->is_connected = TRUE;
    return 1;
}

static void IgUdpSocket_close_win32(IgUdpSocket* udpsocket) {
    if (udpsocket->fd != INVALID_SOCKET) {
        closesocket(udpsocket->fd);
    }
    IG_NETWORKING_FREE(udpsocket);
}

static int IgUdpSocket_recvfrom_win32(IgUdpSocket* udpsocket, char* buffer, size_t buffer_size,  char* out_src_addr, int* out_src_port) {
    struct sockaddr_storage src_addr;
    int addr_len = sizeof(src_addr);
    char ip_str[INET6_ADDRSTRLEN];
    int port;
    int bytes;
    
    bytes = recvfrom(udpsocket->fd, buffer, (int)buffer_size, 0, 
                    (struct sockaddr*)&src_addr, &addr_len);
    if (bytes == SOCKET_ERROR) {
        return -1;
    }

    if (out_src_addr || out_src_port) {
        if (src_addr.ss_family == AF_INET6) {
            InetNtopA(AF_INET6, &((struct sockaddr_in6*)&src_addr)->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(((struct sockaddr_in6*)&src_addr)->sin6_port);
        } else {
            InetNtopA(AF_INET, &((struct sockaddr_in*)&src_addr)->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(((struct sockaddr_in*)&src_addr)->sin_port);
        }

        if (out_src_addr) strcpy(out_src_addr, ip_str);
        if (out_src_port) *out_src_port = port;
    }

    return bytes;
}

static int IgUdpSocket_sendto_win32(IgUdpSocket* udpsocket, const char* buffer, size_t buffer_size, const char* dest_addr, int dest_port) {
    struct sockaddr_storage addr;
    int bytes;
    
    /* Use connected socket if no destination specified */
    if (!dest_addr && udpsocket->is_connected) {
        bytes = send(udpsocket->fd, buffer, (int)buffer_size, 0);
        if (bytes == SOCKET_ERROR) {
            return -1;
        }
        return bytes;
    }

    memset(&addr, 0, sizeof(addr));
    
    if (udpsocket->protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((u_short)dest_port);
        InetPtonA(AF_INET6, dest_addr, &addr6->sin6_addr);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((u_short)dest_port);
        InetPtonA(AF_INET, dest_addr, &addr4->sin_addr);
    }

    bytes = sendto(udpsocket->fd, buffer, (int)buffer_size, 0, 
                      (struct sockaddr*)&addr, sizeof(addr));
    if (bytes == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEWOULDBLOCK) return 0;
        return -1;
    }
    return bytes;
}

#else /* _WIN32 */

static int IgNetworking_init_posix(void) {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;  // Ignore SIGPIPE
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);  // Apply the change
    return 1;
}

static void IgNetworking_shutdown_posix(void) {
    
}

static int IgTcpSocket_resolve_address(const char* hostname, int port, IgIProtocol protocol, struct sockaddr_storage* addr) {
    struct addrinfo hints, *res;
    char port_str[16]; /* 4294967296 (32bit integer litmit, 10 characters long) */
    
    memset(&hints, 0, sizeof(hints));
    switch (protocol) {
    case IG_IPV4: hints.ai_family = AF_INET; break;
    case IG_IPV6: hints.ai_family = AF_INET6; break;
    }
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        return 0;
    }
    
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 1;
}

static IgTcpSocket* IgTcpSocket_listen_posix(const char* hostname, int port, IgIProtocol protocol) {
    IgTcpSocket* tcpsocket;
    int option = 1;
    struct sockaddr_storage addr;
    
    tcpsocket = IG_NETWORKING_MALLOC(sizeof(*tcpsocket));
    if (!tcpsocket) return NULL;
    memset(tcpsocket, 0, sizeof(*tcpsocket));
    
    tcpsocket->fd = socket((protocol == IG_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (tcpsocket->fd < 0) {
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    /* Set SO_REUSEADDR */
    setsockopt(tcpsocket->fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    
    /* Bind */
    if (!IgTcpSocket_resolve_address(hostname, port, protocol, &addr)) {
        close(tcpsocket->fd);
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    if (bind(tcpsocket->fd, (struct sockaddr*)&addr, (protocol == IG_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) < 0) {
        close(tcpsocket->fd);
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    /* Listen */
    if (listen(tcpsocket->fd, SOMAXCONN) < 0) {
        close(tcpsocket->fd);
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    return tcpsocket;
}

static IgTcpSocket* IgTcpSocket_accept_posix(IgTcpSocket* server) {
    IgTcpSocket* client;
    socklen_t addrlen;
    
    client = IG_NETWORKING_MALLOC(sizeof(*client));
    if (!client) return NULL;
    memset(client, 0, sizeof(*client));
    
    addrlen = sizeof(client->addr);
    client->fd = accept(server->fd, (struct sockaddr*)&client->addr, &addrlen);
    
    if (client->fd < 0) {
        IG_NETWORKING_FREE(client);
        return NULL;
    }
    
    return client;
}

static IgTcpSocket* IgTcpSocket_connect_posix(const char* hostname, int port, IgIProtocol protocol) {
    IgTcpSocket* tcpsocket;
    struct sockaddr_storage addr;
    
    tcpsocket = IG_NETWORKING_MALLOC(sizeof(*tcpsocket));
    if (!tcpsocket) return NULL;
    memset(tcpsocket, 0, sizeof(*tcpsocket));
    
    tcpsocket->fd = socket((protocol == IG_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (tcpsocket->fd < 0) {
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    /* Resolve address */
    if (!IgTcpSocket_resolve_address(hostname, port, protocol, &addr)) {
        close(tcpsocket->fd);
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    /* Connect */
    if (connect(tcpsocket->fd, (struct sockaddr*)&addr, (protocol == IG_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) < 0) {
        close(tcpsocket->fd);
        IG_NETWORKING_FREE(tcpsocket);
        return NULL;
    }
    
    return tcpsocket;
}

static void IgTcpSocket_close_posix(IgTcpSocket* tcpsocket) {
    char buffer[1024];
    ssize_t bytes_read;
    /* shutdown further socket io */
    shutdown(tcpsocket->fd, SHUT_WR);
    /* drain the socket (read until we get 0 to make sure the other side closed the socket) */
    while ((bytes_read = read(tcpsocket->fd, buffer, sizeof(buffer))) > 0);
    /* finally close the socket */
    close(tcpsocket->fd);
    IG_NETWORKING_FREE(tcpsocket);
}

static int IgTcpSocket_read_posix(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    ssize_t bytes = read(tcpsocket->fd, buffer, buffer_size);
    if (bytes < 0) return -1;
    return (int)bytes;
}

static int IgTcpSocket_peek_posix(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    ssize_t bytes = recv(tcpsocket->fd, buffer, buffer_size, MSG_PEEK);

    if (bytes < 0) {
        return -1;
    }

    return (int)bytes;
}

static int IgTcpSocket_write_posix(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size) {
    ssize_t bytes = write(tcpsocket->fd, buffer, buffer_size);
    if (bytes < 0) return -1;
    return (int)bytes;
}

static IgUdpSocket* IgUdpSocket_bind_posix(const char* hostname, int port, IgIProtocol protocol) {
    IgUdpSocket* udpsocket;
    struct sockaddr_storage addr;
    
    udpsocket = IG_NETWORKING_MALLOC(sizeof(*udpsocket));
    if (!udpsocket) return NULL;
    memset(udpsocket, 0, sizeof(*udpsocket));

    udpsocket->fd = socket(protocol == IG_IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (udpsocket->fd < 0) {
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    
    if (protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        if (hostname) inet_pton(AF_INET6, hostname, &addr6->sin6_addr);
        else addr6->sin6_addr = in6addr_any;
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        if (hostname) inet_pton(AF_INET, hostname, &addr4->sin_addr);
        else addr4->sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(udpsocket->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(udpsocket->fd);
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    udpsocket->protocol = protocol;
    memcpy(&udpsocket->bound_addr, &addr, sizeof(addr));
    return udpsocket;
}

static IgUdpSocket* IgUdpSocket_create_posix(IgIProtocol protocol) {
    IgUdpSocket* udpsocket;
    
    udpsocket = IG_NETWORKING_MALLOC(sizeof(*udpsocket));
    if (!udpsocket) return NULL;
    memset(udpsocket, 0, sizeof(*udpsocket));

    udpsocket->fd = socket(protocol == IG_IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (udpsocket->fd < 0) {
        IG_NETWORKING_FREE(udpsocket);
        return NULL;
    }

    udpsocket->protocol = protocol;
    return udpsocket;
}

static int IgUdpSocket_connect_posix(IgUdpSocket* udpsocket, const char* hostname, int port) {
    struct sockaddr_storage addr;
    if (udpsocket->is_connected) return 0;

    memset(&addr, 0, sizeof(addr));
    
    if (udpsocket->protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        inet_pton(AF_INET6, hostname, &addr6->sin6_addr);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, hostname, &addr4->sin_addr);
    }

    if (connect(udpsocket->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return 0;
    }

    udpsocket->is_connected = 1;
    return 1;
}

static void IgUdpSocket_close_posix(IgUdpSocket* udpsocket) {
    char buffer[1024];
    ssize_t bytes_read;
    /* shutdown further socket io */
    shutdown(udpsocket->fd, SHUT_RDWR);
    /* drain the socket */
    while ((bytes_read = read(udpsocket->fd, buffer, sizeof(buffer))) > 0);
    /* finally close the socket */
    close(udpsocket->fd);
    IG_NETWORKING_FREE(udpsocket);
}

static int IgUdpSocket_recvfrom_posix(IgUdpSocket* udpsocket, char* buffer, size_t buffer_size, char* out_src_addr, int* out_src_port) {
    struct sockaddr_storage src_addr;
    socklen_t addr_len = sizeof(src_addr);
    char ip_str[INET6_ADDRSTRLEN];
    int port;
    ssize_t bytes;
    
    bytes = recvfrom(udpsocket->fd, buffer, buffer_size, 0, 
                           (struct sockaddr*)&src_addr, &addr_len);
    if (bytes < 0) return -1;

    if (out_src_addr || out_src_port) {
        if (src_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&src_addr)->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(((struct sockaddr_in6*)&src_addr)->sin6_port);
        } else {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&src_addr)->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(((struct sockaddr_in*)&src_addr)->sin_port);
        }

        if (out_src_addr) strcpy(out_src_addr, ip_str);
        if (out_src_port) *out_src_port = port;
    }

    return (int)bytes;
}

static int IgUdpSocket_sendto_posix(IgUdpSocket* udpsocket, const char* buffer, size_t buffer_size, const char* dest_addr, int dest_port) {
    struct sockaddr_storage addr;
    
    /* Use connected socket if no destination specified */
    if (!dest_addr && udpsocket->is_connected) {
        return (int)send(udpsocket->fd, buffer, buffer_size, 0);
    }

    memset(&addr, 0, sizeof(addr));
    
    if (udpsocket->protocol == IG_IPV6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)dest_port);
        inet_pton(AF_INET6, dest_addr, &addr6->sin6_addr);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)dest_port);
        inet_pton(AF_INET, dest_addr, &addr4->sin_addr);
    }

    return (int)sendto(udpsocket->fd, buffer, buffer_size, 0, (struct sockaddr*)&addr, sizeof(addr));
}

#endif /* _WIN32 */

IG_NETWORKING_API int IgNetworking_init(void) {
    return IG_NETWORKING_INTERNAL_CALL(IgNetworking_init)();
}

IG_NETWORKING_API void IgNetworking_shutdown(void) {
    IG_NETWORKING_INTERNAL_CALL(IgNetworking_shutdown)();
}

IG_NETWORKING_API IgTcpSocket* IgTcpSocket_listen(const char* hostname, int port, IgIProtocol protocol) {
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_listen)(hostname, port, protocol);
}

IG_NETWORKING_API IgTcpSocket* IgTcpSocket_accept(IgTcpSocket* server) {
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_accept)(server);
}

IG_NETWORKING_API IgTcpSocket* IgTcpSocket_connect(const char* hostname, int port, IgIProtocol protocol) {
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_connect)(hostname, port, protocol);
}

IG_NETWORKING_API void IgTcpSocket_close(IgTcpSocket* tcpsocket) {
    if (tcpsocket == NULL) return;
    IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_close)(tcpsocket);
}

IG_NETWORKING_API int IgTcpSocket_read(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    if (tcpsocket == NULL) return -1;
    if (buffer_size == 0) return 0;
    if (buffer == NULL) return -1;
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_read)(tcpsocket, buffer, buffer_size);
}

IG_NETWORKING_API int IgTcpSocket_peek(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    if (tcpsocket == NULL) return -1;
    if (buffer_size == 0) return 0;
    if (buffer == NULL) return -1;
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_peek)(tcpsocket, buffer, buffer_size);
}

IG_NETWORKING_API int IgTcpSocket_write(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size) {
    if (tcpsocket == NULL) return -1;
    if (buffer_size == 0) return 0;
    if (buffer == NULL) return -1;
    return IG_NETWORKING_INTERNAL_CALL(IgTcpSocket_write)(tcpsocket, buffer, buffer_size);
}

IG_NETWORKING_API int IgTcpSocket_read_entire_buffer(IgTcpSocket* tcpsocket, char* buffer, size_t buffer_size) {
    char* buf = buffer;
    int n;
    
    while (buffer_size > 0) {
        n = IgTcpSocket_read(tcpsocket, buf, buffer_size);
        if (n < 0) return n;
        buf += n;
        buffer_size -= (size_t)n;
    }
    return 0;
}

IG_NETWORKING_API int IgTcpSocket_write_entire_buffer(IgTcpSocket* tcpsocket, const char* buffer, size_t buffer_size) {
    const char* buf = buffer;
    int n;
    
    while (buffer_size > 0) {
        n = IgTcpSocket_write(tcpsocket, buf, buffer_size);
        if (n < 0) return n;
        buf += n;
        buffer_size -= (size_t)n;
    }
    return 0;
}

IG_NETWORKING_API IgUdpSocket* IgUdpSocket_bind(const char* hostname, int port, IgIProtocol protocol) {
    return IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_bind)(hostname, port, protocol);
}

IG_NETWORKING_API IgUdpSocket* IgUdpSocket_create(IgIProtocol protocol) {
    return IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_create)(protocol);
}

IG_NETWORKING_API int IgUdpSocket_connect(IgUdpSocket* udpsocket, const char* hostname, int port) {
    return IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_connect)(udpsocket, hostname, port);
}

IG_NETWORKING_API void IgUdpSocket_close(IgUdpSocket* udpsocket) {
    if (!udpsocket) return;
    IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_close)(udpsocket);
}

IG_NETWORKING_API int IgUdpSocket_recvfrom(IgUdpSocket* udpsocket, char* buffer, size_t buffer_size, char* out_src_addr, int* out_src_port) {
    if (udpsocket == NULL) return -1;
    if (buffer_size == 0) return 0;
    if (buffer == NULL) return -1;
    return IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_recvfrom)(udpsocket, buffer, buffer_size, out_src_addr, out_src_port);
}

IG_NETWORKING_API int IgUdpSocket_sendto(IgUdpSocket* udpsocket, const char* buffer, size_t buffer_size, const char* dest_addr, int dest_port) {
    if (udpsocket == NULL) return -1;
    if (buffer_size == 0) return 0;
    if (buffer == NULL) return -1;
    return IG_NETWORKING_INTERNAL_CALL(IgUdpSocket_sendto)(udpsocket, buffer, buffer_size, dest_addr, dest_port);
}

IG_NETWORKING_API int IgUdpSocket_read(IgUdpSocket* udpsocket, char* buffer, size_t buffer_size) {
    return IgUdpSocket_recvfrom(udpsocket, buffer, buffer_size, NULL, NULL);
}

IG_NETWORKING_API int IgUdpSocket_write(IgUdpSocket* udpsocket, const char* buffer, size_t buffer_size) {
    return IgUdpSocket_sendto(udpsocket, buffer, buffer_size, NULL, 0);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IG_NETWORKING_IMPLEMENTATION */
