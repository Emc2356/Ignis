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

#ifndef IGNIS__WEBSOCKET_H
#define IGNIS__WEBSOCKET_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#pragma clang diagnostic ignored "-Wpadded"
#endif /* __clang__ */

#ifndef IG_WEBSOCKET_API
#define IG_WEBSOCKET_API
#endif /* IG_WEBSOCKET_API */

#include <stddef.h>

typedef enum IgWebSocketError {
    IG_WS_OK                                           =  0,
    
    IG_WS_HS_NO_END                                    = -1,
    IG_WS_HS_REQUEST_LINE_TOO_SMALL                    = -2,
    IG_WS_HS_REQUEST_LINE_MISSING_GET                  = -3,
    IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT = -4,
    IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT             = -5,
    IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION         = -6,
    IG_WS_HS_HTTP_HEADER_MISSING_COLON                 = -7,
    IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE               = -8,
    IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE               = -9,
    IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION            = -10,
    IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION            = -11,
    IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY                 = -12,
    IG_WS_HS_MISSING_HOST                              = -13,
    IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY               = -14,
    IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION             = -15,
    IG_WS_HS_BAD_SEC_WEBSOCKET_KEY                     = -16,
    IG_WS_HS_NO_ACCEPT                                 = -17,
    IG_WS_HS_REJECTED                                  = -18,
    
    /* the user of this library needs to handle IG_WS_CONNECTION_CLOSED and IG_WS_SOCKET_IO_FAILED */
    IG_WS_CONNECTION_CLOSED                            = -19,
    IG_WS_SOCKET_IO_FAILED                             = -20,
    /* automatically handled by the library (by closing and sending appropriate response) */
    IG_WS_FRAME_CONTROL_TOO_BIG                        = -21,
    IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED           = -22,
    IG_WS_FRAME_UNEXPECTED_OPCODE                      = -23,
    IG_WS_FRAME_UNEXPECTED_MASKED                      = -24,
    IG_WS_FRAME_EXPECTED_MASKED                        = -25,
    IG_WS_UTF8_SHORT                                   = -26,
    IG_WS_UTF8_INVALID                                 = -27,
    /* if the websocket state is OPEN then the user needs to handle IG_WS_FRAME_CLOSE_SENT otherwise it was already handled */
    IG_WS_FRAME_CLOSE_SENT                             = -28
} IgWebSocketError;

typedef enum IgWebSocketMessageKind {
    IG_WS_MESSAGE_KIND_TEXT   = 0x01,
    IG_WS_MESSAGE_KIND_BIN    = 0x02
} IgWebSocketMessageKind;

typedef struct IgWebSocketMessage {
    IgWebSocketMessageKind kind;
    unsigned char* payload;
    size_t payload_length;
    size_t payload_capacity;
} IgWebSocketMessage;

typedef enum IgWebSocketState {
    IG_WS_STATE_CONNECTING = 0x00,
    IG_WS_STATE_OPEN       = 0x01,
    IG_WS_STATE_CLOSING    = 0x02,
    IG_WS_STATE_CLOSED     = 0x03
} IgWebSocketState;

typedef void*(*IgWebSocketReallocFn)(void* allocptr, void* ptr, size_t old_size, size_t new_size);
/* a positive return value is how many bytes were read/written */
/* a return value of 0 means EOF */
/* a negative value means an error */
typedef int(*IgWebSocketReadFn)(void* tcpsocket, char* buffer, size_t buffer_size);
typedef int(*IgWebSocketPeekFn)(void* tcpsocket, char* buffer, size_t buffer_size);
typedef int(*IgWebSocketWriteFn)(void* tcpsocket, const char* buffer, size_t buffer_size);
typedef void(*IgWebSocketCloseFn)(void* tcpsocket);
typedef struct IgWebSocket {
    /* holds the last error  */
    IgWebSocketError error;
    /* if `tcpsocket` refers to client or server socket, will be set when a handshake is initiated */
    int is_client;
    /* how much data the websocket is allowed to send per frame */
    size_t chunk_size;
    /* the state that the websocket is in */
    IgWebSocketState state;
    
    /* the socket that websocket operates on */
    void* tcpsocket;
    /* functions that operate on `tcpsocket` */
    IgWebSocketReadFn readfn;
    IgWebSocketPeekFn peekfn;
    IgWebSocketWriteFn writefn;
    IgWebSocketCloseFn closefn;
    
    /* websocket requires a lot of allocations for messages so it is designed to be used with an arena allocator */
    /* the pointer that is pased to `reallocfunc` */
    void* reallocptr;
    /* the function that websocket calls to allocate memory for messages */
    IgWebSocketReallocFn reallocfn;
} IgWebSocket;

typedef struct IgWebSocketHttpHeader {
    const char* name;
    int name_length;
    const char* value;
    int value_length;
    int total_length;
} IgWebSocketHttpHeader;

typedef struct IgWebSocketHandshakeInfo {
    /* public */
    const char* endpoint;
    const char* host;
    
    IgWebSocketError error;
    /* the rest of the heders that this implementation didnt parse */
    IgWebSocketHttpHeader* headers;
    size_t headers_count;
    size_t headers_capacity;
    
    /* private */
    const char* SecWebSocketKey;
    char* handshake_buffer;
    int handshake_capacity;
    int handshake_length;
} IgWebSocketHandshakeInfo;

IG_WEBSOCKET_API const char* IgWebSocketError_to_string(IgWebSocketError error);
IG_WEBSOCKET_API const char* IgWebSocketError_to_human(IgWebSocketError error);

/* server handshake */
/* starts parsing the client handshake */
IG_WEBSOCKET_API int IgWebSocket_server_handshake_initiate(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info);
/* accept the client handshake */
IG_WEBSOCKET_API int IgWebSocket_server_handshake_accept(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info);
/* reject the client handshake based on handshake_info.error */
IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_error(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info);
/* reject the client handshake for authentication failure */
IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_auth(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info);
/* reject the client handshake for another reason */
IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_other(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info, const char* reason);

/* client handshake */
/* @TODO(param) add a const char** rejection_reason */
IG_WEBSOCKET_API int IgWebSocket_client_handshake(IgWebSocket* ws, const char* host, const char* endpoint, const IgWebSocketHttpHeader* headers, size_t header_count);

IG_WEBSOCKET_API int IgWebSocket_send_message(IgWebSocket* ws, const void* payload, size_t payload_length, IgWebSocketMessageKind kind);
IG_WEBSOCKET_API int IgWebSocket_read_message(IgWebSocket* ws, IgWebSocketMessage* message);
IG_WEBSOCKET_API void IgWebSocket_close(IgWebSocket* ws);

/* even if there was a failure while reading a message, the message should still be freed to avoid leaks */
IG_WEBSOCKET_API void IgWebSocket_free_message(IgWebSocket* ws, IgWebSocketMessage* message);

IG_WEBSOCKET_API const char* IgWebSocket_get_closing_reason(IgWebSocketMessage* message);
IG_WEBSOCKET_API int IgWebSocket_get_closing_reason_length(IgWebSocketMessage* message);
IG_WEBSOCKET_API int IgWebSocket_get_closing_status_code(IgWebSocketMessage* message);

/* 0-999
 *  Status codes in the range 0-999 are not used.
 * 
 * 1000-2999
 *  Status codes in the range 1000-2999 are reserved for definition by
 *  this protocol, its future revisions, and extensions specified in a
 *  permanent and readily available public specification.
 * 
 * 3000-3999
 *  Status codes in the range 3000-3999 are reserved for use by
 *  libraries, frameworks, and applications.  These status codes are
 *  registered directly with IANA.  The interpretation of these codes
 *  is undefined by this protocol.
 * 
 * 4000-4999
 *  Status codes in the range 4000-4999 are reserved for private use
 *  and thus can't be registered.  Such codes can be used by prior
 *  agreements between WebSocket applications.  The interpretation of
 *  these codes is undefined by this protocol.
 */
/* 1000 - No error */
#define IG_WEBSOCKET_STATUS_NORMAL_CLOSURE 1000
/* 1001 - Peer is "going away" (e.g., server shutdown, browser tab closed) */
#define IG_WEBSOCKET_STATUS_GOING_AWAY 1001
/* 1002 - Protocol violation (e.g., malformed WebSocket frame), should not occur */
#define IG_WEBSOCKET_STATUS_PROTOCOL_ERROR 1002
/* 1003 - Unsupported data type (e.g., binary data when only text is allowed) */
#define IG_WEBSOCKET_STATUS_UNSUPPORTED_DATA 1003
/* 1007 - Invalid payload data (e.g., non-UTF-8 text in a text frame) */
#define IG_WEBSOCKET_STATUS_INVALID_FRAME_PAYLOAD_DATA 1007
/* 1008 - Policy violation (e.g., unauthorized, rate limit exceeded) */
#define IG_WEBSOCKET_STATUS_POLICY_VIOLATION 1008
/* 1009 - Message too large (e.g., exceeds max allowed frame size) */
#define IG_WEBSOCKET_STATUS_MESSAGE_TOO_BIG 1009
/* 1010 - Mandatory extension missing (e.g., "permessage-deflate" required but not supported) */
#define IG_WEBSOCKET_STATUS_MANDATORY_EXT 1010
/* 1011 - Internal server error (generic fatal error on server side) */
#define IG_WEBSOCKET_STATUS_INTERNAL_SERVER_ERROR 1011
/* 1015 - TLS handshake failed (used when WebSocket is over HTTPS/WSS) */
#define IG_WEBSOCKET_STATUS_TLS_HANDSHAKE 1015

/* the code MUST be at most 2 bytes and buffer_length MUST be at most 123, anything over 123 will be truncated */
IG_WEBSOCKET_API void IgWebSocket_close_with_reason(IgWebSocket* ws, unsigned int code, const void* buffer, size_t buffer_length);


/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IGNIS__WEBSOCKET_H */

/* A simpler sync echo server with ignis_websocket.h and ignis_networking.h */
#if 0
    /* errors with -Weverything */
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-function-type-strict"
    #endif /* __clang__ */
    
    #define IG_WEBSOCKET_IMPLEMENTATION
    #define IG_NETWORKING_IMPLEMENTATION
    #include "ignis_websocket.h"
    #include "ignis_networking.h"
    
    #include <stdio.h>
    
    
    static void* mrealloc(void* ptru, void* ptr, size_t old_size, size_t new_size) {
        (void) ptru;
        (void) old_size;
        return realloc(ptr, new_size);
    }
    
    #define HOST "127.0.0.1"
    #define PORT 9001
    
    int main(void) {
        IgWebSocketHandshakeInfo handshake_info;
        IgTcpSocket* server_tcpsocket;
        IgTcpSocket* client_tcpsocket;
        IgWebSocket client_ws;
        IgWebSocketMessage message;
        int total_connections = 0;
    
        IgNetworking_init();
        
        client_ws.tcpsocket = NULL;
        client_ws.chunk_size = 65536;
        client_ws.writefn = (IgWebSocketWriteFn)IgTcpSocket_write;
        client_ws.readfn = (IgWebSocketReadFn)IgTcpSocket_read;
        client_ws.peekfn = (IgWebSocketPeekFn)IgTcpSocket_peek;
        client_ws.closefn = (IgWebSocketCloseFn)IgTcpSocket_close;
        client_ws.reallocfn = mrealloc;
        
        server_tcpsocket = IgTcpSocket_listen(HOST, PORT, IG_IPV4);
        if (!server_tcpsocket) {
            printf("[ERROR] Failed to create server socket\n");
            puts(strerror(errno));
            return 1;
        }
        printf("[INFO] Listening on <%s:%d>...\n", HOST, PORT);
        
        while ((client_tcpsocket = IgTcpSocket_accept(server_tcpsocket))) {
            printf("=======================================\n");
            client_ws.tcpsocket = client_tcpsocket;
            total_connections += 1;
            
            if (!IgWebSocket_server_handshake_initiate(&client_ws, &handshake_info)) {
                printf("[ERROR] Failed to initiate server handshake: %s\n", IgWebSocketError_to_human(handshake_info.error));
                if (!IgWebSocket_server_handshake_reject_error(&client_ws, &handshake_info)) return 1;
                continue;
            }
            if (!IgWebSocket_server_handshake_accept(&client_ws, &handshake_info)) {
                printf("[ERROR] Failed to accept client's handshake\n");
                continue;
            }
            
            while (1) {
                if (!IgWebSocket_read_message(&client_ws, &message)) {
                    if (client_ws.error == IG_WS_FRAME_CLOSE_SENT) {
                        if (client_ws.state == IG_WS_STATE_CLOSING) {
                            IgWebSocket_close(&client_ws);
                        }
                        printf("[ERROR] client closed connection\n");
                    } else if (client_ws.state != IG_WS_STATE_CLOSED) {
                        printf("[ERROR]: %s\n", IgWebSocketError_to_string(client_ws.error));
                        printf("[ERROR] %s\n", strerror(errno));
                        IgWebSocket_close(&client_ws);
                    }
                    IgWebSocket_free_message(&client_ws, &message);
                    break;
                } else {
                    printf("[INFO] received %d bytes of %s\n", (int)message.payload_length, message.kind == IG_WS_MESSAGE_KIND_TEXT ? "TEXT" : "BIN");
                    IgWebSocket_send_message(&client_ws, message.payload, message.payload_length, message.kind);
                    IgWebSocket_free_message(&client_ws, &message);
                }
            }
            
            if (total_connections == 247) {
                break;
            }
        }
        
        return 0;
    }
    
    /* errors with -Weverything */
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif /* __clang__ */
#endif /* 0 */

/* the UTF8 verifying and SHA1/base64 encoding was taken from here https://github.com/tsoding/cws/blob/master/src/cws.c */
#ifdef IG_WEBSOCKET_IMPLEMENTATION

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wswitch-default"
#pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif /* __clang__ */

#include <stdint.h> /* uint32_t uint8_t UINT16_MAX */
#include <stdio.h> /* sprintf */
#include <ctype.h> /* isspace */
#include <string.h> /* memset strcmp memcpy strncmp strncasecmp memchr strchr strcpy strlen */
#include <stdlib.h> /* rand */

/* ==============================================UTILITIES============================================== */

static void* IgWebSocket__malloc(IgWebSocket* ws, size_t size) {
    return ws->reallocfn(ws->reallocptr, NULL, 0, size);
}

static void* IgWebSocket__realloc(IgWebSocket* ws, void* ptr, size_t old_size, size_t new_size) {
    return ws->reallocfn(ws->reallocptr, ptr, old_size, new_size);
}

static void IgWebSocket__free(IgWebSocket* ws, void* ptr, size_t size) {
    ws->reallocfn(ws->reallocptr, ptr, size, 0);
}

static int IgWebSocket__read_entire_buffer(IgWebSocket* ws, unsigned char* buffer, size_t size) {
    int bytes_read = 0;
    while (size > 0) {
        bytes_read = ws->readfn(ws->tcpsocket, (char*)buffer, size);
        if (bytes_read == 0) {
            ws->error = IG_WS_CONNECTION_CLOSED;
            return 0;
        } else if (bytes_read < 0) {
            ws->error = IG_WS_SOCKET_IO_FAILED;
            return 0;
        } 
        buffer += bytes_read;
        size -= (size_t)bytes_read;
    }
    return 1;
}

static int IgWebSocket__write_entire_buffer(IgWebSocket* ws, const void* buffer_, size_t size) {
    int bytes_written = 0;
    const char* buffer = (const char*)buffer_;
    while (size > 0) {
        bytes_written = ws->writefn(ws->tcpsocket, buffer, size);
        if (bytes_written == 0) {
            ws->error = IG_WS_CONNECTION_CLOSED;
            return 0;
        } else if (bytes_written < 0) {
            ws->error = IG_WS_SOCKET_IO_FAILED;
            return 0;
        }
        buffer += bytes_written;
        size -= (size_t)bytes_written;
    }
    return 1;
}

/* ===============================================HANDSHAKE=============================================== */

static void IgWebSocket__free_handshake_info(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info) {
    if (handshake_info->handshake_buffer) {
        IgWebSocket__free(ws, handshake_info->handshake_buffer, (size_t)handshake_info->handshake_capacity);
    }
    if (handshake_info->headers) {
        IgWebSocket__free(ws, handshake_info->headers, (size_t)handshake_info->headers_capacity * sizeof(*handshake_info->headers));
    }
}

static char* IgWebSocket__strcat(IgWebSocket* ws, const char* str1, const char* str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char* result = IgWebSocket__malloc(ws, len1 + len2 + 1);
    if (!result) {
        return NULL;
    }
    strcpy(result, str1);
    strcpy(result + len1, str2);
    result[len1 + len2] = '\0';
    return result;
}

static int IgWebSocket__get_handshake_size(const char* handshake, int len) {
    int i = 0;
    while (i < len-3) {
        if (handshake[i] == '\r' && handshake[i + 1] == '\n' && handshake[i + 2] == '\r' && handshake[i + 3] == '\n') {
            return i;
        }
        i++;
    }
    return -1;
}

static int IgWebSocket__get_line_size(const char* handshake) {
    int i = 0;
    int len = (int)strlen(handshake);
    while (i < len-1) {
        if (handshake[i] == '\r' && handshake[i + 1] == '\n') {
            return i;
        }
        i++;
    }
    return 0;
}

/* returns endpoint size or negative for error */
static int IgWebSocket__parse_request_line(char* request_line, int request_line_len, char** endpoint) {
    char* path_end;
    size_t path_len;
    char* http_version;

    if (request_line_len < 14) return -1;
    
    if (strncmp(request_line, "GET ", 4) != 0) return -2;

    path_end = strchr(request_line + 4, ' ');
    if (path_end == NULL || path_end >= request_line + request_line_len) return -3;

    path_len = (size_t)(path_end - (request_line + 4));

    if (request_line[4] != '/') return -4;

    http_version = path_end + 1;
    if (strncmp(http_version, "HTTP/1.1", 8) != 0) return -5;

    *endpoint = request_line + 4;
    return (int)path_len;
}

static int IgWebSocket__parse_HttpHeader(const char* handshake, size_t handshake_size, IgWebSocketHttpHeader* http_header) {
    const char* colon;
    const char* value_start;
    const char* end;
    const char* value_end;
    int remaining_size;

    http_header->name = NULL;
    http_header->name_length = 0;
    http_header->value = NULL;
    http_header->value_length = 0;
    http_header->total_length = 0;

    if (handshake_size == 0) return 0;

    colon = memchr(handshake, ':', handshake_size);
    if (colon == NULL) return -1;

    http_header->name = handshake;
    http_header->name_length = (int)(colon - handshake);

    while (http_header->name_length > 0 && isspace(http_header->name[http_header->name_length - 1])) {
        http_header->name_length--;
    }

    value_start = colon + 1;
    remaining_size = (int)(handshake_size - (size_t)(value_start - handshake));

    while (remaining_size > 0 && isspace(*value_start)) {
        value_start++;
        remaining_size--;
    }

    http_header->value = value_start;
    
    end = memchr(value_start, '\r', (size_t)remaining_size);
    if (end == NULL) {
        end = handshake + handshake_size;
    }
    
    value_end = end;
    while (value_end > http_header->value && isspace(value_end[-1])) {
        value_end--;
    }

    http_header->value_length = (int)(value_end - http_header->value);
    http_header->total_length = (int)(end - handshake);

    return 1;
}

static int IgWebSocket__header_contains_word(const IgWebSocketHttpHeader* header, const char* word) {
    const char* ptr = header->value;
    const char* end = ptr + header->value_length;
    const char* token_start = NULL;
    size_t token_len = 0;

    while (ptr < end) {
        while (ptr < end && isspace(*ptr)) {
            ptr++;
        }
        if (ptr >= end) {
            break;
        }

        token_start = ptr;
        
        while (ptr < end && *ptr != ',' && !isspace(*ptr)) {
            ptr++;
        }

        token_len = (size_t)(ptr - token_start);
        if (token_len == strlen(word) && strncasecmp(token_start, word, token_len) == 0) {
            return 1;
        }

        while (ptr < end && (*ptr == ',' || isspace(*ptr))) {
            ptr++;
        }
    }

    return 0;
}

static const char* IgWebSocket__get_failure_http_response(IgWebSocketError error) {
    switch (error) {
    case IG_WS_HS_NO_END:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 55\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Handshake error: No end of request found (\\r\\n\\r\\n)";
    case IG_WS_HS_REQUEST_LINE_TOO_SMALL:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 49\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Request line too short (minimum 'GET / HTTP/1.1')";
    case IG_WS_HS_REQUEST_LINE_MISSING_GET:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 34\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Request must start with GET method";
    case IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 39\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Missing space after endpoint in request";
    case IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 32\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Missing endpoint in request line";
    case IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 38\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Invalid HTTP version (must be HTTP/1.1)";
    case IG_WS_HS_HTTP_HEADER_MISSING_COLON:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 35\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Header line missing colon separator";
    case IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE:
    case IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 60\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Upgrade header missing or invalid (must contain 'websocket')";
    case IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION:
    case IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 61\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Connection header missing or invalid (must contain 'Upgrade')";
    case IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 32\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Missing Sec-WebSocket-Key header";
    case IG_WS_HS_MISSING_HOST:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 19\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Missing Host header";
    case IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 34\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Duplicate Sec-WebSocket-Key header";
    case IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION:
        return "HTTP/1.1 426 Upgrade Required\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 57\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Unsupported WebSocket version (only version 13 supported)";
    case IG_WS_HS_BAD_SEC_WEBSOCKET_KEY:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 31\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Invalid Sec-WebSocket-Key value";
    case IG_WS_HS_NO_ACCEPT:
        return "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 35\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Missing Sec-WebSocket-Accept header";
    case IG_WS_OK:
    case IG_WS_HS_REJECTED:
    case IG_WS_CONNECTION_CLOSED:
    case IG_WS_FRAME_CONTROL_TOO_BIG:
    case IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED:
    case IG_WS_FRAME_CLOSE_SENT:
    case IG_WS_FRAME_UNEXPECTED_OPCODE:
    case IG_WS_UTF8_SHORT:
    case IG_WS_UTF8_INVALID:
    case IG_WS_FRAME_EXPECTED_MASKED:
    case IG_WS_FRAME_UNEXPECTED_MASKED:
    case IG_WS_SOCKET_IO_FAILED:
    default:
        return "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 33\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Unknown WebSocket handshake error";
    }
}

/* start of modified teenysha1.h */
    /* errors with -Weverything */
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #endif /* __clang__ */
    /*
    * TeenySHA1 - a header only implementation of the SHA1 algorithm in C. Based
    * on the implementation in boost::uuid::details. Translated to C from
    * https://github.com/mohaps/TinySHA1
    *
    * SHA1 Wikipedia Page: http://en.wikipedia.org/wiki/SHA-1
    *
    * Copyright (c) 2012-25 SAURAV MOHAPATRA <mohaps@gmail.com>
    * Copyright (c) 2025    ALEXEY KUTEPOV   <reximkut@gmail.com>
    *
    * Permission to use, copy, modify, and distribute this software for any
    * purpose with or without fee is hereby granted, provided that the above
    * copyright notice and this permission notice appear in all copies.
    *
    * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
    */
    typedef uint32_t digest32_t[5];
    typedef uint8_t digest8_t[20];
    
    typedef struct {
        digest32_t digest;
        uint8_t block[64];
        size_t block_byte_index;
        size_t byte_count;
    } SHA1;
    
    static void sha1_reset(SHA1 *sha1);
    static void sha1_process_block(SHA1 *sha1, const void* const start, const void* const end);
    static void sha1_process_byte(SHA1 *sha1, uint8_t octet);
    static void sha1_process_bytes(SHA1 *sha1, const void* const data, size_t len);
    static const uint32_t* sha1_get_digest(SHA1 *sha1, digest32_t digest);
    static const uint8_t* sha1_get_digest_bytes(SHA1 *sha1, digest8_t digest);
    
    static uint32_t sha1__left_rotate(uint32_t value, size_t count) {
        return (value << count) ^ (value >> (32-count));
    }
    
    static void sha1__process_block(SHA1 *sha1) {
        uint32_t w[80];
        size_t i;
        uint32_t f = 0;
        uint32_t k = 0;
        uint32_t temp, a, b, c, d, e;
        for (i = 0; i < 16; i++) {
            w[i]  = (sha1->block[i*4 + 0] << 24);
            w[i] |= (sha1->block[i*4 + 1] << 16);
            w[i] |= (sha1->block[i*4 + 2] << 8);
            w[i] |= (sha1->block[i*4 + 3]);
        }
        for (i = 16; i < 80; i++) {
            w[i] = sha1__left_rotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
        }
    
        a = sha1->digest[0];
        b = sha1->digest[1];
        c = sha1->digest[2];
        d = sha1->digest[3];
        e = sha1->digest[4];
    
        for (i=0; i<80; ++i) {
            f = 0;
            k = 0;
    
            if (i<20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i<40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i<60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            temp = sha1__left_rotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = sha1__left_rotate(b, 30);
            b = a;
            a = temp;
        }
    
        sha1->digest[0] += a;
        sha1->digest[1] += b;
        sha1->digest[2] += c;
        sha1->digest[3] += d;
        sha1->digest[4] += e;
    }
    
    static void sha1_reset(SHA1 *sha1) {
        sha1->digest[0] = 0x67452301;
        sha1->digest[1] = 0xEFCDAB89;
        sha1->digest[2] = 0x98BADCFE;
        sha1->digest[3] = 0x10325476;
        sha1->digest[4] = 0xC3D2E1F0;
        sha1->block_byte_index = 0;
        sha1->byte_count = 0;
    }
    
    static void sha1_process_byte(SHA1 *sha1, uint8_t octet) {
        sha1->block[sha1->block_byte_index++] = octet;
        ++sha1->byte_count;
        if(sha1->block_byte_index == 64) {
            sha1->block_byte_index = 0;
            sha1__process_block(sha1);
        }
    }
    
    static void sha1_process_block(SHA1 *sha1, const void* const start, const void* const end) {
        const uint8_t* begin = (const uint8_t*)(start);
        const uint8_t* finish = (const uint8_t*)(end);
        while(begin != finish) {
            sha1_process_byte(sha1, *begin);
            begin++;
        }
    }
    
    static void sha1_process_bytes(SHA1 *sha1, const void* const data, size_t len) {
        const uint8_t* block = (const uint8_t*)(data);
        sha1_process_block(sha1, block, block + len);
    }
    
    static const uint32_t* sha1_get_digest(SHA1 *sha1, digest32_t digest) {
        size_t bitCount = sha1->byte_count * 8;
        sha1_process_byte(sha1, 0x80);
        if (sha1->block_byte_index > 56) {
            while (sha1->block_byte_index != 0) {
                sha1_process_byte(sha1, 0);
            }
            while (sha1->block_byte_index < 56) {
                sha1_process_byte(sha1, 0);
            }
        } else {
            while (sha1->block_byte_index < 56) {
                sha1_process_byte(sha1, 0);
            }
        }
        sha1_process_byte(sha1, 0);
        sha1_process_byte(sha1, 0);
        sha1_process_byte(sha1, 0);
        sha1_process_byte(sha1, 0);
        sha1_process_byte(sha1, (unsigned char)((bitCount>>24) & 0xFF));
        sha1_process_byte(sha1, (unsigned char)((bitCount>>16) & 0xFF));
        sha1_process_byte(sha1, (unsigned char)((bitCount>>8 ) & 0xFF));
        sha1_process_byte(sha1, (unsigned char)((bitCount)     & 0xFF));
    
        memcpy(digest, sha1->digest, 5 * sizeof(uint32_t));
        return digest;
    }
    
    static const uint8_t* sha1_get_digest_bytes(SHA1 *sha1, digest8_t digest) {
        digest32_t d32;
        size_t di = 0;
        sha1_get_digest(sha1, d32);
        digest[di++] = ((d32[0] >> 24) & 0xFF);
        digest[di++] = ((d32[0] >> 16) & 0xFF);
        digest[di++] = ((d32[0] >> 8) & 0xFF);
        digest[di++] = ((d32[0]) & 0xFF);
    
        digest[di++] = ((d32[1] >> 24) & 0xFF);
        digest[di++] = ((d32[1] >> 16) & 0xFF);
        digest[di++] = ((d32[1] >> 8) & 0xFF);
        digest[di++] = ((d32[1]) & 0xFF);
    
        digest[di++] = ((d32[2] >> 24) & 0xFF);
        digest[di++] = ((d32[2] >> 16) & 0xFF);
        digest[di++] = ((d32[2] >> 8) & 0xFF);
        digest[di++] = ((d32[2]) & 0xFF);
    
        digest[di++] = ((d32[3] >> 24) & 0xFF);
        digest[di++] = ((d32[3] >> 16) & 0xFF);
        digest[di++] = ((d32[3] >> 8) & 0xFF);
        digest[di++] = ((d32[3]) & 0xFF);
    
        digest[di++] = ((d32[4] >> 24) & 0xFF);
        digest[di++] = ((d32[4] >> 16) & 0xFF);
        digest[di++] = ((d32[4] >> 8) & 0xFF);
        digest[di++] = ((d32[4]) & 0xFF);
        return digest;
    }
    /* errors with -Weverything */
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif /* __clang__ */
/* end of modified teenysha1.h */

/* start of modified b64.h */
    #define b64_encode_out_len(in_len) (((in_len) + 2)/3*4)
    static size_t b64_encode(const unsigned char* in, size_t in_len, char* out) {
        const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char padding = '=';
        size_t out_len = 0;
        size_t in_cur = 0;
        uint32_t group = 0;
        while (in_cur + 3 <= in_len) {
            group = 0;
            group |= ((uint32_t)(in[in_cur++]))<<(2*8);
            group |= ((uint32_t)(in[in_cur++]))<<(1*8);
            group |= ((uint32_t)(in[in_cur++]))<<(0*8);
            out[out_len++] = alpha[(group>>(3*6))&0x3F];
            out[out_len++] = alpha[(group>>(2*6))&0x3F];
            out[out_len++] = alpha[(group>>(1*6))&0x3F];
            out[out_len++] = alpha[(group>>(0*6))&0x3F];
        }
    
        switch (in_len - in_cur) {
            case 0: break;
            case 1: {
                group = 0;
                group |= ((uint32_t)in[in_cur++])<<(2*8);
                out[out_len++] = alpha[(group>>(3*6))&0x3F];
                out[out_len++] = alpha[(group>>(2*6))&0x3F];
                out[out_len++] = padding;
                out[out_len++] = padding;
            } break;
            case 2: {
                group = 0;
                group |= ((uint32_t)in[in_cur++])<<(2*8);
                group |= ((uint32_t)in[in_cur++])<<(1*8);
                out[out_len++] = alpha[(group>>(3*6))&0x3F];
                out[out_len++] = alpha[(group>>(2*6))&0x3F];
                out[out_len++] = alpha[(group>>(1*6))&0x3F];
                out[out_len++] = padding;
            } break;
            default: return 0;
        }
    
        return out_len;
    }
/* end of modified b64.h */

static char* IgWebSocket__encode_accept_key(IgWebSocket* ws, const char* key) {
    const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char* key_to_encode = IgWebSocket__strcat(ws, key, GUID);
    SHA1 sha1;
    digest8_t digest;
    char* sec_websocket_accept;
    const size_t sec_websocket_accept_len = b64_encode_out_len(sizeof(digest)) + 1;

    sha1_reset(&sha1);
    sha1_process_bytes(&sha1, key_to_encode, strlen(key_to_encode));
    sha1_get_digest_bytes(&sha1, digest);
    
    IgWebSocket__free(ws, key_to_encode, strlen(key_to_encode) + 1);
    
    sec_websocket_accept = IgWebSocket__malloc(ws, sec_websocket_accept_len);
    b64_encode((void*)digest, sizeof(digest), sec_websocket_accept);
    sec_websocket_accept[sec_websocket_accept_len-1] = '\0';
    
    return sec_websocket_accept;
}

static char* IgWebSocket__format_client_handshake_request(IgWebSocket* ws, const char* host, const char* endpoint, const IgWebSocketHttpHeader* headers, size_t header_count) {
    size_t size = 0;
    char* request;
    char* ptr;
    size_t i;
    char ws_key[41] = "SWduaXNXZWJTb2NrZXRJbXBsZW1lbnRhdGlvbg=="; 
    
    /* required headers */
    size += strlen("GET ") + strlen(endpoint) + strlen(" HTTP/1.1\r\n");
    size += strlen("Host: ") + strlen(host) + strlen("\r\n");
    size += strlen("Upgrade: websocket\r\n");
    size += strlen("Connection: keep-alive, Upgrade\r\n");
    size += strlen("Sec-WebSocket-Version: 13\r\n");
    size += strlen("Sec-WebSocket-Key: ") + sizeof(ws_key) + strlen("\r\n");
    
    /* custom headers */
    for (i = 0; i < header_count; i++) {
        size += (size_t)headers[i].name_length + strlen(": ") + (size_t)headers[i].value_length + strlen("\r\n");
    }
    
    size += strlen("\r\n");
    
    request = (char*)IgWebSocket__malloc(ws, size + 1);
    if (!request) {
        return NULL;
    }
    
    ptr = request;
    
    ptr += sprintf(ptr, "GET %s HTTP/1.1\r\n", endpoint);
    
    ptr += sprintf(ptr, "Host: %s\r\n", host);
    
    ptr += sprintf(ptr, "Upgrade: websocket\r\n");
    ptr += sprintf(ptr, "Connection: keep-alive, Upgrade\r\n");
    ptr += sprintf(ptr, "Sec-WebSocket-Key: %s\r\n", ws_key);
    ptr += sprintf(ptr, "Sec-WebSocket-Version: 13\r\n");
    
    for (i = 0; i < header_count; i++) {
        memcpy(ptr, headers[i].name, (size_t)headers[i].name_length);
        ptr += headers[i].name_length;
        *ptr++ = ':';
        *ptr++ = ' ';
        memcpy(ptr, headers[i].value, (size_t)headers[i].value_length);
        ptr += headers[i].value_length;
        *ptr++ = '\r';
        *ptr++ = '\n';
    }
    
    *ptr++ = '\r';
    *ptr++ = '\n';
    *ptr = '\0';
    
    return request;
}

static int IgWebSocket__read_http_request(IgWebSocket* ws, char** buffer, int* buffer_length, int* buffer_capacity) {
    /* @TODO: it is still possible that there is no end because the whole handshake is not received */
    int bytes_read;
    
    *buffer_length = 0;
    *buffer_capacity = 128;
    *buffer = (char*)IgWebSocket__realloc(ws, NULL, 0, (size_t)*buffer_capacity);
    
    for (;;) {
        bytes_read = ws->peekfn(ws->tcpsocket, *buffer, (size_t)*buffer_capacity-1);
        if (bytes_read <= 0) {
            ws->error = IG_WS_HS_NO_END;
            IgWebSocket__free(ws, *buffer, (size_t)*buffer_capacity);
            return 0;
        }
        if (bytes_read == *buffer_capacity-1) {
            *buffer_capacity *= 2;
            *buffer = (char*)IgWebSocket__realloc(ws, *buffer, (size_t)*buffer_capacity/2, (size_t)*buffer_capacity);
            continue;
        }
        
        /* locate \r\n\r\n */
        *buffer_length = IgWebSocket__get_handshake_size(*buffer, *buffer_capacity);
        if (*buffer_length == -1) {
            ws->error = IG_WS_HS_NO_END;
            IgWebSocket__free(ws, *buffer, (size_t)*buffer_capacity);
            return 0;
        }
        break;
    }
    
    /* consume the http request from the socket */
    if (!IgWebSocket__read_entire_buffer(ws, (unsigned char*)*buffer, (size_t)*buffer_length+4)) return 0;
    (*buffer)[*buffer_length] = '\0';
    
    return 1;
}

IG_WEBSOCKET_API const char* IgWebSocketError_to_string(IgWebSocketError error) {
    switch (error) {
    case IG_WS_OK:
        return "IG_WS_OK";
    case IG_WS_HS_NO_END:
        return "IG_WS_HS_NO_END";
    case IG_WS_HS_REQUEST_LINE_TOO_SMALL:
        return "IG_WS_HS_REQUEST_LINE_TOO_SMALL";
    case IG_WS_HS_REQUEST_LINE_MISSING_GET:
        return "IG_WS_HS_REQUEST_LINE_MISSING_GET";
    case IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT:
        return "IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT";
    case IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT:
        return "IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT";
    case IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION:
        return "IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION";
    case IG_WS_HS_HTTP_HEADER_MISSING_COLON:
        return "IG_WS_HS_HTTP_HEADER_MISSING_COLON";
    case IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE:
        return "IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE";
    case IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE:
        return "IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE";
    case IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION:
        return "IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION";
    case IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION:
        return "IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION";
    case IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY:
        return "IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY";
    case IG_WS_HS_MISSING_HOST:
        return "IG_WS_HS_MISSING_HOST";
    case IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY:
        return "IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY";
    case IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION:
        return "IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION";
    case IG_WS_HS_BAD_SEC_WEBSOCKET_KEY:
        return "IG_WS_HS_BAD_SEC_WEBSOCKET_KEY";
    case IG_WS_HS_NO_ACCEPT:
        return "IG_WS_HS_NO_ACCEPT";
    case IG_WS_HS_REJECTED:
        return "IG_WS_HS_REJECTED";
    case IG_WS_CONNECTION_CLOSED:
        return "IG_WS_CONNECTION_CLOSED";
    case IG_WS_SOCKET_IO_FAILED:
        return "IG_WS_SOCKET_IO_FAILED";
    case IG_WS_FRAME_CONTROL_TOO_BIG:
        return "IG_WS_FRAME_CONTROL_TOO_BIG";
    case IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED:
        return "IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED";
    case IG_WS_FRAME_CLOSE_SENT:
        return "IG_WS_FRAME_CLOSE_SENT";
    case IG_WS_FRAME_UNEXPECTED_OPCODE:
        return "IG_WS_FRAME_UNEXPECTED_OPCODE";
    case IG_WS_FRAME_EXPECTED_MASKED:
        return "IG_WS_FRAME_EXPECTED_MASKED";
    case IG_WS_FRAME_UNEXPECTED_MASKED:
        return "IG_WS_FRAME_UNEXPECTED_MASKED";
    case IG_WS_UTF8_SHORT:
        return "IG_WS_UTF8_SHORT";
    case IG_WS_UTF8_INVALID:
        return "IG_WS_UTF8_INVALID";
    }
}

IG_WEBSOCKET_API const char* IgWebSocketError_to_human(IgWebSocketError error) {
    switch (error) {
        case IG_WS_OK:
            return "No error";
        case IG_WS_HS_NO_END:
            return "Handshake error: No end of request found (\\r\\n\\r\\n)";
        case IG_WS_HS_REQUEST_LINE_TOO_SMALL:
            return "Handshake error: Too short (minimum 'GET / HTTP/1.1' required)";
        case IG_WS_HS_REQUEST_LINE_MISSING_GET:
            return "Handshake error: Must start with 'GET' method";
        case IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT:
            return "Handshake error: Missing space after endpoint";
        case IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT:
            return "Handshake error: Missing endpoint (must start with '/')";
        case IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION:
            return "Handshake error: Invalid HTTP version (must be HTTP/1.1)";
        case IG_WS_HS_HTTP_HEADER_MISSING_COLON:
            return "Handshake error: Missing colon separator in header";
        case IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE:
            return "Handshake error: Upgrade header must contain 'websocket'";
        case IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE:
            return "Handshake error: Missing required Upgrade header";
        case IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION:
            return "Handshake error: Connection header must contain 'Upgrade'";
        case IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION:
            return "Handshake error: Missing required Connection header";
        case IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY:
            return "Handshake error: Missing Sec-WebSocket-Key header";
        case IG_WS_HS_MISSING_HOST:
            return "Handshake error: Missing required Host header";
        case IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY:
            return "Handshake error: Duplicate Sec-WebSocket-Key header";
        case IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION:
            return "Handshake error: Invalid or unsupported Sec-WebSocket-Version (must be 13)";
        case IG_WS_HS_BAD_SEC_WEBSOCKET_KEY:
            return "Handshake error: Invalid Sec-WebSocket-Key header";
        case IG_WS_HS_NO_ACCEPT:
            return "Handshake error: Missing Sec-WebSocket-Accept header";
        case IG_WS_HS_REJECTED:
            return "Handshake error: Rejected";
        case IG_WS_CONNECTION_CLOSED:
            return "Connection closed";
        case IG_WS_SOCKET_IO_FAILED:
            return "Unknown error occured when operating on tcpsocket";
        case IG_WS_FRAME_CONTROL_TOO_BIG:
            return "Frame control too big";
        case IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED:
            return "Frame reserved bits not negotiated";
        case IG_WS_FRAME_CLOSE_SENT:
            return "Frame close sent";
        case IG_WS_FRAME_UNEXPECTED_OPCODE:
            return "Frame unexpected opcode";
        case IG_WS_FRAME_EXPECTED_MASKED:
            return "Frame was expected to be masked";
        case IG_WS_FRAME_UNEXPECTED_MASKED:
            return "Frame was not expected to be masked";
        case IG_WS_UTF8_SHORT:
            return "UTF8 short";
        case IG_WS_UTF8_INVALID:
            return "UTF8 invalid";
    }
}

IG_WEBSOCKET_API int IgWebSocket_server_handshake_initiate(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info) {
    int endpoint_size;
    int handshake_size;
    int request_line_size;
    int have_upgrade_header;
    int have_connection_header;
    int err;
    char* endpoint;
    char* handshake;
    IgWebSocketHttpHeader http_header;
    
    handshake_info->host = NULL;
    handshake_info->endpoint = NULL;
    handshake_info->SecWebSocketKey = NULL;
    handshake_info->error = IG_WS_OK;
    handshake_info->headers = NULL;
    handshake_info->headers_count = 0;
    handshake_info->headers_capacity = 0;
    handshake_info->handshake_buffer = NULL;
    handshake_info->handshake_capacity = 0;
    handshake_info->handshake_length = 0;
    have_upgrade_header = 0;
    have_connection_header = 0;
    ws->error = IG_WS_OK;
    ws->is_client = 0;
    
    if (!IgWebSocket__read_http_request(ws, &handshake_info->handshake_buffer, &handshake_info->handshake_length, &handshake_info->handshake_capacity)) {
        handshake_info->error = ws->error;
        goto fail;
    }
    handshake = handshake_info->handshake_buffer;
    handshake_size = handshake_info->handshake_length;
    
    /* verify and parse http header */
    request_line_size = IgWebSocket__get_line_size(handshake);
    endpoint_size = IgWebSocket__parse_request_line(handshake, request_line_size, &endpoint);
    if (endpoint_size < 0) {
        if      (endpoint_size == -1) handshake_info->error = IG_WS_HS_REQUEST_LINE_TOO_SMALL;
        else if (endpoint_size == -2) handshake_info->error = IG_WS_HS_REQUEST_LINE_MISSING_GET;
        else if (endpoint_size == -3) handshake_info->error = IG_WS_HS_REQUEST_LINE_MISSING_SPACE_AFTER_ENDPOINT;
        else if (endpoint_size == -4) handshake_info->error = IG_WS_HS_REQUEST_LINE_MISSING_ENDPOINT;
        else if (endpoint_size == -5) handshake_info->error = IG_WS_HS_REQUEST_LINE_INVALID_HTTP_VERSION;
        
        ws->error = handshake_info->error;
        goto fail;
    }
    handshake_size -= request_line_size + 2;
    handshake += request_line_size + 2;

    handshake_info->endpoint = endpoint;
    endpoint[endpoint_size] = '\0';
    
    for (;;) {
        if (handshake_size <= 0) break;
        
        err = IgWebSocket__parse_HttpHeader(handshake, (size_t)handshake_size, &http_header);
        if (err == -1) {
            handshake_info->error = IG_WS_HS_HTTP_HEADER_MISSING_COLON;
            ws->error = IG_WS_HS_HTTP_HEADER_MISSING_COLON;
            goto fail;
        } else if (err == 0) {
            break;
        }
        /* null terminate the name and value */
        handshake[http_header.name_length] = '\0';
        handshake[http_header.total_length] = '\0';
        
        if (strcmp(http_header.name, "Host") == 0) {
            handshake_info->host = http_header.value;
        } else if (strcmp(http_header.name, "Upgrade") == 0) {
            if (!IgWebSocket__header_contains_word(&http_header, "websocket")) {
                handshake_info->error = IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE;
                ws->error = IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE;
                goto fail;
            }
            have_upgrade_header = 1;
        } else if (strcmp(http_header.name, "Connection") == 0) {
            if (!IgWebSocket__header_contains_word(&http_header, "upgrade")) {
                handshake_info->error = IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION;
                ws->error = IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION;
                goto fail;
            }
            have_connection_header = 1;
        } else if (strcmp(http_header.name, "Sec-WebSocket-Key") == 0) {
            if (handshake_info->SecWebSocketKey == NULL) {
                handshake_info->SecWebSocketKey = http_header.value;
            } else {
                handshake_info->error = IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY;
                ws->error = IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY;
                goto fail;
            }
                
        } else if (strcmp(http_header.name, "Sec-WebSocket-Version") == 0) {
            if (strcmp(http_header.value, "13") != 0) {
                handshake_info->error = IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION;
                ws->error = IG_WS_HS_INVALID_SEC_WEBSOCKET_VERSION;
                goto fail;
            }
        } else if (strcmp(http_header.name, "Sec-WebSocket-Extensions") == 0) {
            /* @TODO(WebSocketExtensions): permessage-deflate */
        } else {
            if (handshake_info->headers_count >= handshake_info->headers_capacity) {
                handshake_info->headers = IgWebSocket__realloc(ws, handshake_info->headers,
                    handshake_info->headers_capacity * sizeof(*handshake_info->headers), 
                    (handshake_info->headers_capacity * 2 + 1) * sizeof(*handshake_info->headers));
                handshake_info->headers_capacity *= 2;
                handshake_info->headers_capacity += 1;
            }
            handshake_info->headers[handshake_info->headers_count++] = http_header;
        }
        
        handshake_size -= http_header.total_length + 2;
        handshake += http_header.total_length + 2;
    }

    if (!have_upgrade_header) {
        handshake_info->error = IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE;
        ws->error = IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE;
        goto fail;
    }
    
    if (!have_connection_header) {
        handshake_info->error = IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION;
        ws->error = IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION;
        goto fail;
    }

    if (handshake_info->SecWebSocketKey == NULL) {
        handshake_info->error = IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY;
        ws->error = IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY;
        goto fail;
    }
    
    if (handshake_info->host == NULL) {
        handshake_info->error = IG_WS_HS_MISSING_HOST;
        ws->error = IG_WS_HS_MISSING_HOST;
        goto fail;
    }
    
    return 1;
    fail:
        return 0;
}

IG_WEBSOCKET_API int IgWebSocket_server_handshake_accept(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info) {
    const char* response_head = "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: ";
    const char* response_end = "\r\n\r\n";
    char* encoded_key = IgWebSocket__encode_accept_key(ws, handshake_info->SecWebSocketKey);
    
    if (!IgWebSocket__write_entire_buffer(ws, response_head, strlen(response_head))) return 0;
    if (!IgWebSocket__write_entire_buffer(ws, encoded_key, strlen(encoded_key))) return 0;
    if (!IgWebSocket__write_entire_buffer(ws, response_end, strlen(response_end))) return 0;
    
    IgWebSocket__free(ws, encoded_key, strlen(encoded_key) + 1);
    IgWebSocket__free_handshake_info(ws, handshake_info);
    
    ws->state = IG_WS_STATE_OPEN;
    
    return 1;
}

IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_error(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info) {
    const char* error_message = IgWebSocket__get_failure_http_response(handshake_info->error);
    
    IgWebSocket__write_entire_buffer(ws, error_message, strlen(error_message));
    
    IgWebSocket__free_handshake_info(ws, handshake_info);
    
    ws->closefn(ws->tcpsocket);
    ws->state = IG_WS_STATE_CLOSED;
    
    return 1;
}

IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_auth(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info) {
    const char* error_message = "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: 32\r\n"
                                "Connection: close\r\n"
                                "Sec-WebSocket-Version: 21\r\n"
                                "\r\n"
                                "Authentication failed";
    
    IgWebSocket__write_entire_buffer(ws, error_message, strlen(error_message));
    
    IgWebSocket__free_handshake_info(ws, handshake_info);
    
    ws->closefn(ws->tcpsocket);
    ws->state = IG_WS_STATE_CLOSED;
    
    return 1;
}

IG_WEBSOCKET_API int IgWebSocket_server_handshake_reject_other(IgWebSocket* ws, IgWebSocketHandshakeInfo* handshake_info, const char* reason) {
   size_t reason_len = strlen(reason);
   int i;
   int len;
   const char* response_header = "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: ";
   const char* response_middle = "\r\n"
                                "Connection: close\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
   char length_str[16];
   char* p = length_str;
   int n = (int)reason_len;
   do {
       *p++ = '0' + (n % 10);
       n /= 10;
   } while (n > 0);
   *p = '\0';
   
   // Reverse the digits
   len = (int)(p - length_str);
   for (i = 0; i < len/2; i++) {
       char tmp = length_str[i];
       length_str[i] = length_str[len-1-i];
       length_str[len-1-i] = tmp;
   }

   
   // Send response in parts
   if (!IgWebSocket__write_entire_buffer(ws, response_header, strlen(response_header))) return 0;
   if (!IgWebSocket__write_entire_buffer(ws, length_str, strlen(length_str))) return 0;
   if (!IgWebSocket__write_entire_buffer(ws, response_middle, strlen(response_middle))) return 0;
   if (!IgWebSocket__write_entire_buffer(ws, reason, reason_len)) return 0;

   // Cleanup and close
   IgWebSocket__free_handshake_info(ws, handshake_info);
   ws->closefn(ws->tcpsocket);
   ws->state = IG_WS_STATE_CLOSED;
   
   return 1;
}

IG_WEBSOCKET_API int IgWebSocket_client_handshake(IgWebSocket* ws, const char* host, const char* endpoint, const IgWebSocketHttpHeader* headers, size_t header_count) {
    char* request = IgWebSocket__format_client_handshake_request(ws, host, endpoint, headers, header_count);
    char* response_base = NULL;
    char* response;
    int result = 0;
    int response_length = 0;
    int response_capacity = 0;
    int err;
    IgWebSocketHttpHeader http_header;
    int was_sec_websocket_key_found = 0;
    int have_upgrade_header = 0;
    int have_connection_header = 0;
    
    if (!IgWebSocket__write_entire_buffer(ws, request, strlen(request))) {
        goto cleanup;
    }

    if (!IgWebSocket__read_http_request(ws, &response_base, &response_length, &response_capacity)) {
        goto cleanup;
    }
    response = response_base;
    
    if (strncmp(response, "HTTP/1.1 101 Switching Protocols\r\n", 34) == 0) {
        response += 34;
        response_length -= 34;
        
        for (;;) {
            if (response_length <= 0) break;
            
            err = IgWebSocket__parse_HttpHeader(response, (size_t)response_length, &http_header);
            if (err == -1) {
                ws->error = IG_WS_HS_HTTP_HEADER_MISSING_COLON;
                goto cleanup;
            } else if (err == 0) {
                break;
            }
            /* null terminate the name and value */
            response[http_header.name_length] = '\0';
            response[http_header.total_length] = '\0';
            
             if (strcmp(http_header.name, "Upgrade") == 0) {
                if (!IgWebSocket__header_contains_word(&http_header, "websocket")) {
                    ws->error = IG_WS_HS_HTTP_HEADER_INVALID_UPGRADE;
                    goto cleanup;
                }
                have_upgrade_header = 1;
            } else if (strcmp(http_header.name, "Connection") == 0) {
                if (!IgWebSocket__header_contains_word(&http_header, "upgrade")) {
                    ws->error = IG_WS_HS_HTTP_HEADER_INVALID_CONNECTION;
                    goto cleanup;
                }
                have_connection_header = 1;
            } else if (strcmp(http_header.name, "Sec-WebSocket-Key") == 0) {
                if (was_sec_websocket_key_found) {
                    ws->error = IG_WS_HS_DUPLICATE_SEC_WEBSOCKET_KEY;
                    goto cleanup;
                } else {
                    if (strcmp(http_header.value, "A4n+snSCPhrMC3NBSDh9YSu3mAs=") == 0) {
                        was_sec_websocket_key_found = 1;
                    } else {
                        ws->error = IG_WS_HS_BAD_SEC_WEBSOCKET_KEY;
                        goto cleanup;
                    }
                }
            } else if (strcmp(http_header.name, "Sec-WebSocket-Extensions") == 0) {
                /* @TODO(WebSocketExtensions): permessage-deflate */
            } 
            
            response_length -= http_header.total_length + 2;
            response += http_header.total_length + 2;
        }
        
        if (!was_sec_websocket_key_found) {
            ws->error = IG_WS_HS_MISSING_SEC_WEBSOCKET_KEY;
            goto cleanup;
        }
        if (!have_upgrade_header) {
            ws->error = IG_WS_HS_HTTP_HEADER_MISSING_UPGRADE;
            goto cleanup;
        }
        if (!have_connection_header) {
            ws->error = IG_WS_HS_HTTP_HEADER_MISSING_CONNECTION;
            goto cleanup;
        }
    } else {
        ws->error = IG_WS_HS_REJECTED;
        goto cleanup;
    }
    
    ws->is_client = 1;
    result = 1;
    ws->state = IG_WS_STATE_OPEN;
    goto success;
    cleanup:
        ws->state = IG_WS_STATE_CLOSED;
    success:
    
        if (request) {
            IgWebSocket__free(ws, request, strlen(request));
        }
        if (response_base) {
            IgWebSocket__free(ws, response_base, (size_t)response_capacity);
        }
        return result;
}


/* ==============================================WEBSOCKET PROTOCOL============================================== */

/*
 * RFC 6455 - Section 5.2:
 *   This wire format for the data transfer part is described by the ABNF
 *   [RFC5234] given in detail in this section.  (Note that, unlike in
 *   other sections of this document, the ABNF in this section is
 *   operating on groups of bits.  The length of each group of bits is
 *   indicated in a comment.  When encoded on the wire, the most
 *   significant bit is the leftmost in the ABNF).  A high-level overview
 *   of the framing is given in the following figure.  In a case of
 *   conflict between the figure below and the ABNF specified later in
 *   this section, the figure is authoritative.
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-------+-+-------------+-------------------------------+
 *     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 *     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 *     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 *     | |1|2|3|       |K|             |                               |
 *     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 *     |     Extended payload length continued, if payload len == 127  |
 *     + - - - - - - - - - - - - - - - +-------------------------------+
 *     |                               |Masking-key, if MASK set to 1  |
 *     +-------------------------------+-------------------------------+
 *     | Masking-key (continued)       |          Payload Data         |
 *     +-------------------------------- - - - - - - - - - - - - - - - +
 *     :                     Payload Data continued ...                :
 *     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *     |                     Payload Data continued ...                |
 *     +---------------------------------------------------------------+
 *
 *   FIN:  1 bit
 *
 *      Indicates that this is the final fragment in a message.  The first
 *      fragment MAY also be the final fragment.
 *
 *   RSV1, RSV2, RSV3:  1 bit each
 *
 *      MUST be 0 unless an extension is negotiated that defines meanings
 *      for non-zero values.  If a nonzero value is received and none of
 *      the negotiated extensions defines the meaning of such a nonzero
 *      value, the receiving endpoint MUST _Fail the WebSocket
 *      Connection_.
 *
 *   Opcode:  4 bits
 *
 *   Defines the interpretation of the "Payload data".  If an unknown
 *   opcode is received, the receiving endpoint MUST _Fail the
 *   WebSocket Connection_.  The following values are defined.
 *   
 *   *  %x0 denotes a continuation frame
 *   
 *   *  %x1 denotes a text frame
 *   
 *   *  %x2 denotes a binary frame
 *   
 *   *  %x3-7 are reserved for further non-control frames
 *   
 *   *  %x8 denotes a connection close
 *   
 *   *  %x9 denotes a ping
 *   
 *   *  %xA denotes a pong
 *   
 *   *  %xB-F are reserved for further control frames
 *   
 *   Mask:  1 bit
 *   
 *      Defines whether the "Payload data" is masked.  If set to 1, a
 *      masking key is present in masking-key, and this is used to unmask
 *      the "Payload data" as per Section 5.3.  All frames sent from
 *      client to server have this bit set to 1.
 *   
 *   Payload length:  7 bits, 7+16 bits, or 7+64 bits
 *   
 *      The length of the "Payload data", in bytes: if 0-125, that is the
 *      payload length.  If 126, the following 2 bytes interpreted as a
 *      16-bit unsigned integer are the payload length.  If 127, the
 *      following 8 bytes interpreted as a 64-bit unsigned integer (the
 *      most significant bit MUST be 0) are the payload length.  Multibyte
 *      length quantities are expressed in network byte order.  Note that
 *      in all cases, the minimal number of bytes MUST be used to encode
 *      the length, for example, the length of a 124-byte-long string
 *      can't be encoded as the sequence 126, 0, 124.  The payload length
 *      is the length of the "Extension data" + the length of the
 *      "Application data".  The length of the "Extension data" may be
 *      zero, in which case the payload length is the length of the
 *      "Application data".
 *   
 *   Masking-key:  0 or 4 bytes
 *
 *      All frames sent from the client to the server are masked by a
 *      32-bit value that is contained within the frame.  This field is
 *      present if the mask bit is set to 1 and is absent if the mask bit
 *      is set to 0.  See Section 5.3 for further information on client-
 *      to-server masking.
 *
 *   Payload data:  (x+y) bytes
 *
 *      The "Payload data" is defined as "Extension data" concatenated
 *      with "Application data".
 */
typedef enum IgWebSocketOpcode {
    IG_WS_OPCODE_CONT  = 0x0,
    IG_WS_OPCODE_TEXT  = 0x1,
    IG_WS_OPCODE_BIN   = 0x2,
    IG_WS_OPCODE_CLOSE = 0x8,
    IG_WS_OPCODE_PING  = 0x9,
    IG_WS_OPCODE_PONG  = 0xA
} IgWebSocketOpcode;

typedef struct IgWebSocketFrameHeader {
    int fin, rsv1, rsv2, rsv3;
    IgWebSocketOpcode opcode;
    int masked;
    size_t payload_len;
    uint8_t mask[4];
} IgWebSocketFrameHeader;


/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif /* __clang__ */
static int32_t IgWebSocket__utf8_to_char32_fixed(unsigned char* ptr, size_t* size) {
    size_t max_size = *size;
    uint32_t uc;
    unsigned char c;
    if (max_size < 1) return IG_WS_UTF8_SHORT;
    c = (ptr++)[0];

    if ((c & 0x80) == 0) {
        *size = 1;
        return c;
    }
    if ((c & 0xE0) == 0xC0) {
        if (max_size < 2) return IG_WS_UTF8_SHORT;
        *size = 2;
        uc = (c & 0x1F) << 6;
        c = *ptr;
        // Overlong sequence or invalid second.
        if (!uc || (c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
        uc = uc + (c & 0x3F);
        // maximum overlong sequence
        if (uc <= 0x7F) return IG_WS_UTF8_INVALID;
        // UTF-16 surrogate pairs
        if (0xD800 <= uc && uc <= 0xDFFF) return IG_WS_UTF8_INVALID;
        return uc;
    }
    if ((c & 0xF0) == 0xE0) {
        if (max_size < 3) return IG_WS_UTF8_SHORT;
        *size = 3;
        uc = (c & 0x0F) << 12;
        c = ptr++[0];
        if ((c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
        uc += (c & 0x3F) << 6;
        c = ptr++[0];
        // Overlong sequence or invalid last
        if (!uc || (c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
        uc = uc + (c & 0x3F);
        // maximum overlong sequence
        if (uc <= 0x7FF) return IG_WS_UTF8_INVALID;
        // UTF-16 surrogate pairs
        if (0xD800 <= uc && uc <= 0xDFFF) return IG_WS_UTF8_INVALID;
        return uc;
    }
    if (max_size < 4) return IG_WS_UTF8_SHORT;
    if ((c & 0xF8) != 0xF0) return IG_WS_UTF8_INVALID;
    *size = 4;
    uc = (c & 0x07) << 18;
    c = ptr++[0];
    if ((c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
    uc += (c & 0x3F) << 12;
    c = ptr++[0];
    if ((c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
    uc += (c & 0x3F) << 6;
    c = ptr++[0];
    // Overlong sequence or invalid last
    if (!uc || (c & 0xC0) != 0x80) return IG_WS_UTF8_INVALID;
    uc = uc + (c & 0x3F);
    // UTF-16 surrogate pairs
    if (0xD800 <= uc && uc <= 0xDFFF) return IG_WS_UTF8_INVALID;
    // maximum overlong sequence
    if (uc <= 0xFFFF) return IG_WS_UTF8_INVALID;
    // Maximum valid Unicode number
    if (uc > 0x10FFFF) return IG_WS_UTF8_INVALID;
    return uc;
}
/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

static void IgWebSocketMessage__append(IgWebSocket* ws, IgWebSocketMessage* message, unsigned char c) {
    if (message->payload_length >= message->payload_capacity) {
        message->payload = IgWebSocket__realloc(ws, message->payload, message->payload_capacity, (message->payload_capacity*2) + 1);
        message->payload_capacity = (message->payload_capacity*2) + 1;
    }
    message->payload[message->payload_length++] = c;
}

static void IgWebSocketMessage__extend_capacity(IgWebSocket* ws, IgWebSocketMessage* message, size_t extend_by) {
    while (message->payload_capacity < message->payload_length + extend_by) {
        message->payload = IgWebSocket__realloc(ws, message->payload, message->payload_capacity, message->payload_capacity * 2 + 1);
        message->payload_capacity = message->payload_capacity * 2 + 1;
    }
}

static void IgWebSocket__extend_unfinished_utf8(IgWebSocket* ws, IgWebSocketMessage* message, size_t pos) {
    unsigned char c = message->payload[pos];
    size_t size = 0;
    if ((c & 0x80) == 0) {
        size = 1;
    } else if ((c & 0xE0) == 0xC0) {
        size = 2;
    } else if ((c & 0xF0) == 0xE0) {
        size = 3;
    } else {
        size = 4;
    }
    while (message->payload_length - pos < size) IgWebSocketMessage__append(ws, message, 0x80);
}

static int IgWebSocketOpcode__is_control(IgWebSocketOpcode opcode) {
    /*
     * RFC 6455 - Section 5.5:
     *   Control frames are identified by opcodes where the most significant
     *   bit of the opcode is 1.  Currently defined opcodes for control frames
     *   include 0x8 (Close), 0x9 (Ping), and 0xA (Pong).  Opcodes 0xB-0xF are
     *   reserved for further control frames yet to be defined.
     *   
     *   [...]
     */
    return 0x8 <= opcode && opcode <= 0xF;
}

static int IgWebSocket__send_frame(IgWebSocket* ws, IgWebSocketFrameHeader* header, const void* payload) {
    unsigned char packed_length[8];
    unsigned char data;
    size_t i;
    unsigned char chunk[1024];
    size_t chunk_size;
    
    data = 0;
    if (header->fin) data |= (1 << 7);
    if (header->rsv1) data |= (1 << 6);
    if (header->rsv2) data |= (1 << 5);
    if (header->rsv3) data |= (1 << 4);
    data |= (unsigned char)header->opcode;

    if (!IgWebSocket__write_entire_buffer(ws, &data, 1)) return 0;

    /* mask bit */
    data = ws->is_client ? (1 << 7) : 0;
    if (header->payload_len < 126) {
        data |= (unsigned char) header->payload_len;
        if (!IgWebSocket__write_entire_buffer(ws, &data, 1)) return 0;
    } else if (header->payload_len <= UINT16_MAX) {
        data |= 126;
        packed_length[0] = (unsigned char)(header->payload_len >> (8 * 1)) & 0xFF;
        packed_length[1] = (unsigned char)(header->payload_len >> (8 * 0)) & 0xFF;
        
        if (!IgWebSocket__write_entire_buffer(ws, &data, 1)) return 0;
        if (!IgWebSocket__write_entire_buffer(ws, packed_length, 2)) return 0;
    } else if (header->payload_len > UINT16_MAX) {
        data |= 127;
        packed_length[0] = (unsigned char)(header->payload_len >> (8 * 7)) & 0xFF;
        packed_length[1] = (unsigned char)(header->payload_len >> (8 * 6)) & 0xFF;
        packed_length[2] = (unsigned char)(header->payload_len >> (8 * 5)) & 0xFF;
        packed_length[3] = (unsigned char)(header->payload_len >> (8 * 4)) & 0xFF;
        packed_length[4] = (unsigned char)(header->payload_len >> (8 * 3)) & 0xFF;
        packed_length[5] = (unsigned char)(header->payload_len >> (8 * 2)) & 0xFF;
        packed_length[6] = (unsigned char)(header->payload_len >> (8 * 1)) & 0xFF;
        packed_length[7] = (unsigned char)(header->payload_len >> (8 * 0)) & 0xFF;

        if (!IgWebSocket__write_entire_buffer(ws, &data, 1)) return 0;
        if (!IgWebSocket__write_entire_buffer(ws, packed_length, 8)) return 0;
    }

    if (header->payload_len) {
        if (ws->is_client) {
            for (i = 0; i < sizeof(header->mask); ++i) {
                header->mask[i] = (unsigned char)(rand() % 0x100);
            }
            if (!IgWebSocket__write_entire_buffer(ws, header->mask, sizeof(header->mask))) return 0;
    
            for (i = 0; i < header->payload_len;) {
                chunk_size = 0;
                while (i < header->payload_len && chunk_size < 1024) {
                    chunk[chunk_size] = ((const unsigned char*)payload)[i] ^ header->mask[i % 4];
                    chunk_size += 1;
                    i += 1;
                }
                if (!IgWebSocket__write_entire_buffer(ws, chunk, chunk_size)) return 0;
            }
        } else {
            if (!IgWebSocket__write_entire_buffer(ws, payload, header->payload_len)) return 0;
        }
    }

    return 1;
}

static int IgWebSocket__read_frame_header(IgWebSocket* ws, IgWebSocketFrameHeader* header) {
    unsigned char data[8];
    int i;
    
    if (!IgWebSocket__read_entire_buffer(ws, data, 2)) return 0;
    
    header->fin         = (data[0] >> 7) & 1;
    header->rsv1        = (data[0] >> 6) & 1;
    header->rsv2        = (data[0] >> 5) & 1;
    header->rsv3        = (data[0] >> 4) & 1;
    header->opcode      = (IgWebSocketOpcode)(data[0] & 0xF);
    header->masked      = (data[1] >> 7) & 1;
    header->payload_len = (data[1] >> 0) & 127;
    
    if (header->payload_len == 126) {
        if (!IgWebSocket__read_entire_buffer(ws, data, 2)) return 0;
        header->payload_len = 0;
        for (i = 0; i < 2; i++) {
            header->payload_len = (header->payload_len << 8) | data[i];
        }
    } else if (header->payload_len == 127) {
        if (!IgWebSocket__read_entire_buffer(ws, data, 8)) return 0;
        header->payload_len = 0;
        for (i = 0; i < 8; i++) {
            header->payload_len = (header->payload_len << 8) | data[i];
        }
    }
    
    if (header->masked) {
        if (!IgWebSocket__read_entire_buffer(ws, header->mask, 4)) return 0;
    }
    
    /*
     * RFC 6455 - Section 5.1:
     *   In the WebSocket Protocol, data is transmitted using a sequence of
     *   frames.  To avoid confusing network intermediaries (such as
     *   intercepting proxies) and for security reasons that are further
     *   discussed in Section 10.3, a client MUST mask all frames that it
     *   sends to the server (see Section 5.3 for further details).  (Note
     *   that masking is done whether or not the WebSocket Protocol is running
     *   over TLS.)  The server MUST close the connection upon receiving a
     *   frame that is not masked.  In this case, a server MAY send a Close
     *   frame with a status code of 1002 (protocol error) as defined in
     *   Section 7.4.1.  A server MUST NOT mask any frames that it sends to
     *   the client.  A client MUST close a connection if it detects a masked
     *   frame.  In this case, it MAY use the status code 1002 (protocol
     *   error) as defined in Section 7.4.1.  (These rules might be relaxed in
     *   a future specification.).
     */
    if (!ws->is_client && !header->masked) {
        ws->error = IG_WS_FRAME_EXPECTED_MASKED;
        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.1: The server MUST close the connection upon receiving a frame that is not masked", 103);
        return 0;
    }
    if (ws->is_client && header->masked) {
        ws->error = IG_WS_FRAME_UNEXPECTED_MASKED;
        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.1: A client MUST close a connection if it detects a masked frame", 86);
        return 0;
    }
    
    /*
     * RFC 6455 - Section 5.5:
     *   All control frames MUST have a payload length of 125 bytes or less
     *   and MUST NOT be fragmented.
     */
    if (IgWebSocketOpcode__is_control(header->opcode) && (header->payload_len > 125 || !header->fin)) {
        ws->error = IG_WS_FRAME_CONTROL_TOO_BIG;
        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.5: All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented", 118);
        return 0;
    }
    
    /*
     * RFC 6455 - Section 5.2:
     * >  RSV1, RSV2, RSV3:  1 bit each
     * >
     * >     MUST be 0 unless an extension is negotiated that defines meanings
     * >     for non-zero values.  If a nonzero value is received and none of
     * >     the negotiated extensions defines the meaning of such a nonzero
     * >     value, the receiving endpoint MUST _Fail the WebSocket
     * >     Connection_.
     */
    if (header->rsv1 || header->rsv2 || header->rsv3) {
        ws->error = IG_WS_FRAME_RESERVED_BITS_NOT_NEGOTIATED;
        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.2: RSV MUST be 0 unless an extension is negotiated that defines meanings for non-zero values", 114);
        return 0;
    }
    
    return 1;
}

IG_WEBSOCKET_API int IgWebSocket_send_message(IgWebSocket* ws, const void* payload_, size_t payload_length, IgWebSocketMessageKind kind) {
    size_t len;
    const char* payload = payload_;
    IgWebSocketFrameHeader header;

    ws->error = IG_WS_OK;
    
    header.opcode = (IgWebSocketOpcode)kind;
    do {
        len = payload_length;
        if (len > ws->chunk_size) len = ws->chunk_size;
        header.fin = payload_length - len == 0;
        header.rsv1 = 0;
        header.rsv2 = 0;
        header.rsv3 = 0;
        header.payload_len = len;
        
        if (!IgWebSocket__send_frame(ws, &header, payload)) return 0;
        header.opcode = IG_WS_OPCODE_CONT;

        payload += len;
        payload_length -= len;
    } while(payload_length > 0);

    return 1;
}

static size_t IgWebSocket__read_frame_payload_chunk(IgWebSocket* ws, IgWebSocketFrameHeader* header, unsigned char* payload, size_t finished_payload_len) {
    size_t unfinished_payload_len;
    int bytes_read;
    size_t i;

    if (finished_payload_len >= header->payload_len) return 0;
    unfinished_payload_len = header->payload_len - finished_payload_len;
    bytes_read = ws->readfn(ws->tcpsocket, (char*)payload, unfinished_payload_len);
    if (bytes_read == 0) {
        ws->error = IG_WS_CONNECTION_CLOSED;
        return 0;
    } else if (bytes_read < 0) {
        ws->error = IG_WS_SOCKET_IO_FAILED;
        return 0;
    }
    if (header->masked) {
        for (i = 0; i < unfinished_payload_len; ++i) {
            payload[i] ^= header->mask[(finished_payload_len + i) % 4];
        }
    }
    return (size_t)bytes_read;
}

static int IgWebSocket__read_frame_into_message(IgWebSocket* ws, IgWebSocketFrameHeader* header, IgWebSocketMessage* message) {
    size_t i;
    size_t bytes_to_read = header->payload_len;
    int bytes_read;
    size_t total_bytes_read = 0;
    
    IgWebSocketMessage__extend_capacity(ws, message, header->payload_len);
    
    while (bytes_to_read) {
        bytes_read = ws->readfn(ws->tcpsocket, (char*)(message->payload + message->payload_length), bytes_to_read);
        if (bytes_read == 0) {
            ws->error = IG_WS_CONNECTION_CLOSED;
            return 0;
        } else if (bytes_read < 0) {
            ws->error = IG_WS_SOCKET_IO_FAILED;
            return 0;
        }
        
        if (header->masked) {
            for (i = 0; i < (size_t)bytes_read; ++i) {
                message->payload[message->payload_length + i] = message->payload[message->payload_length + i] ^ header->mask[(total_bytes_read + i) % 4];
            }
        }
        
        bytes_to_read -= (size_t)bytes_read;
        message->payload_length += (size_t)bytes_read;
        total_bytes_read += (size_t)bytes_read;
    }
    
    return 1;
}

static int IgWebSocket__read_frame_into_payload_pointer(IgWebSocket* ws, IgWebSocketFrameHeader* header, void* payload_buffer_) {
    size_t i;
    size_t bytes_to_read = header->payload_len;
    int bytes_read;
    size_t total_bytes_read = 0;
    unsigned char* payload_buffer = (unsigned char*)payload_buffer_;

    
    while (bytes_to_read) {
        bytes_read = ws->readfn(ws->tcpsocket, (char*)payload_buffer, bytes_to_read);
        if (bytes_read == 0) {
            ws->error = IG_WS_CONNECTION_CLOSED;
            return 0;
        } else if (bytes_read < 0) {
            ws->error = IG_WS_CONNECTION_CLOSED;
            return 0;
        }
        
        if (header->masked) {
            for (i = 0; i < (size_t)bytes_read; ++i) {
                payload_buffer[i] = payload_buffer[i] ^ header->mask[(total_bytes_read + i) % 4];
            }
        }
        
        bytes_to_read -= (size_t)bytes_read;
        payload_buffer += bytes_read;
        total_bytes_read += (size_t)bytes_read;
    }
    
    return 1;
}

IG_WEBSOCKET_API int IgWebSocket_read_message(IgWebSocket* ws, IgWebSocketMessage* message) {
    IgWebSocketFrameHeader header;
    int is_first_fragment = 1;
    
    /* a control frame can have a max payload length of 125 bytes */
    char control_frame_buffer[125];
    /* for close frame handling */
    int close_status;
    
    /* for UTF-8 Handling */
    size_t frame_finished_payload_len;
    size_t verify_pos = 0;
    size_t bytes_read;
    size_t saved_len;
    int ret;
    
    ws->error = IG_WS_OK;
    message->payload = NULL;
    message->payload_length = 0;
    message->payload_capacity = 0;
    
    for (;;) {
        if (!IgWebSocket__read_frame_header(ws, &header)) goto failed;
        if (IgWebSocketOpcode__is_control(header.opcode)) {
            /*
             * RFC 6455 - Section 5.4:
             *   
             *   [...]
             *   
             *       o  An endpoint MUST be capable of handling control frames in the
             *          middle of a fragmented message.
             *   
             *   [...]
             *   
             *   NOTE: If control frames could not be interjected, the latency of a
             *   ping, for example, would be very long if behind a large message.
             *   Hence, the requirement of handling control frames in the middle of a
             *   fragmented message.
             */
            switch (header.opcode) {
            case IG_WS_OPCODE_CLOSE:
                /*
                 * RFC 6455 - Section 5.5.1:
                 *   The Close frame MAY contain a body (the "Application data" portion of
                 *   the frame) that indicates a reason for closing, such as an endpoint
                 *   shutting down, an endpoint having received a frame too large, or an
                 *   endpoint having received a frame that does not conform to the format
                 *   expected by the endpoint.  If there is a body, the first two bytes of
                 *   the body MUST be a 2-byte unsigned integer (in network byte order)
                 *   representing a status code with value /code/ defined in Section 7.4.
                 *   Following the 2-byte integer, the body MAY contain UTF-8-encoded data
                 *   with value /reason/, the interpretation of which is not defined by
                 *   this specification.  This data is not necessarily human readable but
                 *   may be useful for debugging or passing information relevant to the
                 *   script that opened the connection.  As the data is not guaranteed to
                 *   be human readable, clients MUST NOT show it to end users.
                 *
                 *   Close frames sent from client to server must be masked as per
                 *   Section 5.3.
                 * >
                 *   The application MUST NOT send any more data frames after sending a
                 *   Close frame.
                 *
                 *   If an endpoint receives a Close frame and did not previously send a
                 *   Close frame, the endpoint MUST send a Close frame in response.  (When
                 *   sending a Close frame in response, the endpoint typically echos the
                 *   status code it received.)  It SHOULD do so as soon as practical.  An
                 *   endpoint MAY delay sending a Close frame until its current message is
                 *   sent (for instance, if the majority of a fragmented message is
                 *   already sent, an endpoint MAY send the remaining fragments before
                 *   sending a Close frame).  However, there is no guarantee that the
                 *   endpoint that has already sent a Close frame will continue to process
                 *   data.
                 *
                 *   After both sending and receiving a Close message, an endpoint
                 *   considers the WebSocket connection closed and MUST close the
                 *   underlying TCP connection.  The server MUST close the underlying TCP
                 *   connection immediately; the client SHOULD wait for the server to
                 *   close the connection but MAY close the connection at any time after
                 *   sending and receiving a Close message, e.g., if it has not received a
                 *   TCP Close from the server in a reasonable time period.
                 *
                 *   If a client and server both send a Close message at the same time,
                 *   both endpoints will have sent and received a Close message and should
                 *   consider the WebSocket connection closed and close the underlying TCP
                 *   connection.
                 */
                ws->error = IG_WS_FRAME_CLOSE_SENT;
                if (header.payload_len == 0) {
                    IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_NORMAL_CLOSURE, NULL, 0);
                    goto failed;
                } else {
                    if (message->payload_capacity < header.payload_len) {
                        IgWebSocketMessage__extend_capacity(ws, message, header.payload_len - message->payload_capacity);
                    }
                    message->payload_length = 0;
                    if (!IgWebSocket__read_frame_into_message(ws, &header, message)) goto failed;
                    
                    if (header.payload_len < 2) {
                        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.5.1: the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order)", 116);
                        goto failed;
                    }
                    
                    close_status = message->payload[0];
                    close_status = (close_status << 8) | message->payload[1];
                    
                    if (close_status < 1000) {
                        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 7.4.2: Status codes in the range 0-999 are not used.", 72);
                        goto failed;
                    }
                    
                    if ((close_status >= 1000 && close_status < 3000)
                        && close_status != IG_WEBSOCKET_STATUS_NORMAL_CLOSURE
                        && close_status != IG_WEBSOCKET_STATUS_GOING_AWAY
                        && close_status != IG_WEBSOCKET_STATUS_PROTOCOL_ERROR
                        && close_status != IG_WEBSOCKET_STATUS_UNSUPPORTED_DATA
                        && close_status != IG_WEBSOCKET_STATUS_INVALID_FRAME_PAYLOAD_DATA
                        && close_status != IG_WEBSOCKET_STATUS_POLICY_VIOLATION
                        && close_status != IG_WEBSOCKET_STATUS_MESSAGE_TOO_BIG
                        && close_status != IG_WEBSOCKET_STATUS_MANDATORY_EXT
                        && close_status != IG_WEBSOCKET_STATUS_INTERNAL_SERVER_ERROR
                        && close_status != IG_WEBSOCKET_STATUS_TLS_HANDSHAKE) {
                        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 7.4.2: Status codes in the range 1000-2999 are reserved for definition by this protocol [...]", 113);
                        goto failed;
                    }
                    
                    /* first 2 bytes are the status code */
                    verify_pos = 2; 
                    while (verify_pos < message->payload_length) {
                        size_t size = message->payload_length - verify_pos;
                        ret = IgWebSocket__utf8_to_char32_fixed(&message->payload[verify_pos], &size);
                        if (ret < 0) {
                            IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.5.1: [...] the body MAY contain UTF-8-encoded data [...]", 78);
                            goto failed;
                        }
                        verify_pos += size;
                    }
                    ws->state = IG_WS_STATE_CLOSING;
                    
                    return 0;
                }
            case IG_WS_OPCODE_PING:
                /*
                 * RFC 6455 - Section 5.5.2:
                 * >    A Ping frame MAY include "Application data".
                 * >
                 * >    Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in
                 * >    response, unless it already received a Close frame.  It SHOULD
                 * >    respond with Pong frame as soon as is practical.  Pong frames are
                 * >    discussed in Section 5.5.3.
                */
                if (!IgWebSocket__read_frame_into_payload_pointer(ws, &header, control_frame_buffer)) goto failed;
                header.opcode = IG_WS_OPCODE_PONG;
                if (!IgWebSocket__send_frame(ws, &header, control_frame_buffer)) goto failed;
                break;
            case IG_WS_OPCODE_PONG:
                /*
                 * RFC 6455 - Section 5.5.3:
                 *   A Pong frame MAY be sent unsolicited.  This serves as a
                 *   unidirectional heartbeat.  A response to an unsolicited Pong frame is
                 *   not expected.
                 */
                 if (!IgWebSocket__read_frame_into_payload_pointer(ws, &header, control_frame_buffer)) goto failed;
                break;
            case IG_WS_OPCODE_CONT:
            case IG_WS_OPCODE_TEXT:
            case IG_WS_OPCODE_BIN:
            default:
                /*
                 * RFC 6455 - Section 5.2:
                 *
                 *   [...] 
                 *
                 *   Opcode:  4 bits
                 *
                 *   Defines the interpretation of the "Payload data".  If an unknown
                 *   opcode is received, the receiving endpoint MUST _Fail the
                 *   WebSocket Connection_.  The following values are defined.
                 *    
                 *   [...] 
                 */
                ws->error = IG_WS_FRAME_UNEXPECTED_OPCODE;
                IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.2: If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_", 118);
                goto failed;
            }
        } else {
            /*
             * RFC 6455 - Section 5.4:
             * > ...
             * >     The following rules apply to fragmentation:
             * >
             * >         o  An unfragmented message consists of a single frame with the FIN
             * >            bit set (Section 5.2) and an opcode other than 0.
             * >
             * >         o  A fragmented message consists of a single frame with the FIN bit
             * >            clear and an opcode other than 0, followed by zero or more frames
             * >            with the FIN bit clear and the opcode set to 0, and terminated by
             * >            a single frame with the FIN bit set and an opcode of 0.  A
             * >            fragmented message is conceptually equivalent to a single larger
             * >            message whose payload is equal to the concatenation of the
             * >            payloads of the fragments in order; however, in the presence of
             * >            extensions, this may not hold true as the extension defines the
             * >            interpretation of the "Extension data" present.  For instance,
             * >            "Extension data" may only be present at the beginning of the first
             * >            fragment and apply to subsequent fragments, or there may be
             * >            "Extension data" present in each of the fragments that applies
             * >            only to that particular fragment.  In the absence of "Extension
             * >            data", the following example demonstrates how fragmentation works.
             * >
             * >            [...]
             * >
             * >         o  The fragments of one message MUST NOT be interleaved between the
             * >            fragments of another message unless an extension has been
             * >            negotiated that can interpret the interleaving.
             * >
             * >            [...]
             * >
             * >         o  A sender MAY create fragments of any size for non-control
             * >            messages.
             * >
             * >         o  Clients and servers MUST support receiving both fragmented and
             * >            unfragmented messages.
             * >
             * >            [...]
             * >
             * >         o  As a consequence of these rules, all fragments of a message are of
             * >            the same type, as set by the first fragment's opcode.  Since
             * >            control frames cannot be fragmented, the type for all fragments in
             * >            a message MUST be either text, binary, or one of the reserved
             * >            opcodes.
             * >
             * >            [...]
             */
            if (is_first_fragment) {
                switch (header.opcode) {
                case IG_WS_OPCODE_TEXT:
                case IG_WS_OPCODE_BIN:
                    message->kind = (IgWebSocketMessageKind)header.opcode;
                    break;
                case IG_WS_OPCODE_CONT:
                case IG_WS_OPCODE_CLOSE:
                case IG_WS_OPCODE_PING:
                case IG_WS_OPCODE_PONG:
                default:
                    ws->error = IG_WS_FRAME_UNEXPECTED_OPCODE;
                    IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.2: If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_", 118);
                    goto failed;
                }
                is_first_fragment = 0;
            } else {
                if (header.opcode != IG_WS_OPCODE_CONT) {
                    ws->error = IG_WS_FRAME_UNEXPECTED_OPCODE;
                    IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_PROTOCOL_ERROR, "RFC 6455 - Section 5.2: If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_", 118);
                    goto failed;
                }
            }
            /*
             * The format of binary message is not defined by RFC 6455.
             * Meanwhile the format of text is strictly defined as UTF-8,
             */
            if (message->kind == IG_WS_MESSAGE_KIND_BIN) {
                if (!IgWebSocket__read_frame_into_message(ws, &header, message)) goto failed;
            } else {
                frame_finished_payload_len = 0;
                
                IgWebSocketMessage__extend_capacity(ws, message, header.payload_len);
                
                while (frame_finished_payload_len < header.payload_len) {
                    bytes_read = IgWebSocket__read_frame_payload_chunk(ws, &header, message->payload + message->payload_length, frame_finished_payload_len);
                    if (bytes_read == 0) goto failed;
                    message->payload_length += bytes_read;
                    frame_finished_payload_len += bytes_read;
    
                    /* Verifying UTF-8 */
                    while (verify_pos < message->payload_length) {
                        size_t size = message->payload_length - verify_pos;
                        ret = IgWebSocket__utf8_to_char32_fixed(&message->payload[verify_pos], &size);
                        if (ret < 0) {
                            if (ret != IG_WS_UTF8_SHORT) goto bad_utf8_sequence; /* Fail-fast on invalid UTF-8 that is not unfinished UTF-8 */
                            if (header.fin)              goto bad_utf8_sequence; /* Not tolerating unfinished UTF-8 if the message is finished */
                            /* Extending the finished UTF-8 to check if it fixes the problem */
                            saved_len = message->payload_length;
                            IgWebSocket__extend_unfinished_utf8(ws, message, verify_pos);
                            size = message->payload_length - verify_pos;
                            ret = IgWebSocket__utf8_to_char32_fixed(&message->payload[verify_pos], &size);
                            if (ret < 0) goto bad_utf8_sequence;
                            message->payload_length = saved_len;
                            break; /* Tolerating the unfinished UTF-8 sequences if the message is unfinished */
                        }
                        verify_pos += size;
                    }
                }
            }
            /*
             * RFC 6455 - Section 5.2:
             *   [...]
             *
             *   FIN:  1 bit
             *
             *      Indicates that this is the final fragment in a message.  The first
             *      fragment MAY also be the final fragment.
             *
             *   [...]
             */
            if (header.fin) break;
        }
    }

    return 1;
    
    bad_utf8_sequence:
        IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_INVALID_FRAME_PAYLOAD_DATA, "RFC 6455 - Section 5.6: The \"Payload data\" is text data encoded as UTF-8 [...] the whole message MUST contain valid UTF-8.", 123);
        goto failed;
    
    failed:
        if (message->payload) {
            IgWebSocket__free(ws, message->payload, message->payload_capacity);
        }
        memset(message, 0, sizeof(*message));
        return 0;
}

IG_WEBSOCKET_API void IgWebSocket_free_message(IgWebSocket* ws, IgWebSocketMessage* message) {
    ws->error = IG_WS_OK;
    
    if (message->payload) {
        IgWebSocket__free(ws, message->payload, message->payload_capacity);
    }
}

IG_WEBSOCKET_API void IgWebSocket_close(IgWebSocket* ws) {
    IgWebSocket_close_with_reason(ws, IG_WEBSOCKET_STATUS_NORMAL_CLOSURE, NULL, 0);
}

IG_WEBSOCKET_API void IgWebSocket_close_with_reason(IgWebSocket* ws, unsigned int code, const void* buffer, size_t buffer_length) {
    IgWebSocketFrameHeader header;
    unsigned char close_frame[125];
    size_t payload_len = 2;
    
    close_frame[0] = (code >> 8) & 0xFF;
    close_frame[1] = (code >> 0) & 0xFF;       
    
    if (buffer != NULL && buffer_length > 0) {
        if (buffer_length > 123) {
            buffer_length = 123;
        }
        memcpy(close_frame + 2, buffer, buffer_length);
        payload_len += buffer_length;
    }
    
    header.fin = 1;
    header.rsv1 = 0;
    header.rsv2 = 0;
    header.rsv3 = 0;
    header.opcode = IG_WS_OPCODE_CLOSE;
    header.masked = 0;
    header.payload_len = payload_len;
    
    IgWebSocket__send_frame(ws, &header, close_frame);
    
    ws->closefn(ws->tcpsocket);
    ws->state = IG_WS_STATE_CLOSED;
}

IG_WEBSOCKET_API const char* IgWebSocket_get_closing_reason(IgWebSocketMessage* message) {
    return (const char*)(message->payload + 2);
}

IG_WEBSOCKET_API int IgWebSocket_get_closing_reason_length(IgWebSocketMessage* message) {
    return (int)message->payload_length - 2;
}

IG_WEBSOCKET_API int IgWebSocket_get_closing_status_code(IgWebSocketMessage* message) {
    if (message->payload_length < 2) {
        return -1;
    }
    return ((message->payload[0] << 8) | message->payload[1]);
}

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IG_WEBSOCKET_IMPLEMENTATION */
