#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "random.h"
#include "quic_helper.h"

#define MAX_MSG_SENDMMSG 50
#define MAX_MSG_RECVMMSG 50

#define MAX_DATAGRAM_SIZE 1350

#define HTTP_REQ_STREAM_ID 4

struct _quic_base_handler {
    int fd;
    bool independent;
    socklen_t local_len;
    socklen_t peer_len;
    struct sockaddr local;
    struct sockaddr peer;

    quiche_config* config;
    quiche_h3_config* h3_config;
};

struct _quic_conn_handler {
    QuicBaseHandler* handler;
    quiche_conn* conn;
    quiche_h3_conn* h3_conn;
};

static bool set_blocking_mode(int fd, char blocking)
{
    if (fd < 0)
        return false;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;
}

static int bind_connect_addr(int fd, const struct addrinfo* hints, const char* name, const char* str_port, struct sockaddr* addr, socklen_t* addr_len, int (*func)(int, const struct sockaddr*, socklen_t))
{
    struct addrinfo* result = NULL;
    struct addrinfo* next_result = NULL;

    if(getaddrinfo(name, str_port, hints, &result))
    {
        fprintf(stderr, "Unable to find address\n");
        goto FREE;
    }

    next_result = result;

    while(next_result != NULL)
    {
        if (func(fd, next_result->ai_addr, next_result->ai_addrlen) == 0)
            break;

        next_result = next_result->ai_next;
    }

    if(next_result == NULL)
    {
        fprintf(stderr, "Connection refused\n");
        close(fd);
        fd = -1;
        goto FREE;
    }
    *addr = *(next_result->ai_addr);
    *addr_len = next_result->ai_addrlen;

FREE:
    freeaddrinfo(result);
    return fd;
}

static int build_socket(const char* local_hostname, const char* str_local_port, const char* peer_hostname, const char* str_peer_port, struct sockaddr* local, socklen_t* local_len, struct sockaddr* peer, socklen_t* peer_len)
{
    int fd;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if(fd == -1)
    {
        return -1;
    }

    if(local_hostname != NULL || str_local_port != NULL)
    {
        fd = bind_connect_addr(fd, &hints, local_hostname, str_local_port, local, local_len, bind);
        if(fd == -1)
        {
            return -1;
        }
    }

    if(peer_hostname != NULL || str_peer_port != NULL)
    {
        fd = bind_connect_addr(fd, &hints, peer_hostname, str_peer_port, peer, peer_len, connect);
    }

    return fd;
}

static void print_id(const uint8_t* id, size_t len)
{
    printf("id: ");
    for(size_t i = 0; i < len; i++)
    {
        printf("%02x", id[i]);
    }
    putchar('\n');
}

static bool create_conn(QuicConnHandler* handler, const uint8_t* buffer, size_t buf_len)
{
    uint8_t type;
    uint32_t version;
    uint8_t scid[256];
    size_t scid_len = sizeof(scid);
    uint8_t dcid[256];
    size_t dcid_len = sizeof(dcid);
    uint8_t token[256];
    size_t token_len = sizeof(token);
    uint8_t out[MAX_DATAGRAM_SIZE];
    ssize_t out_len;

    printf("%d\n", quiche_header_info(buffer, buf_len, QUICHE_MAX_CONN_ID_LEN, &version, &type, scid, &scid_len, dcid, &dcid_len, token, &token_len));

    printf("%s\n", inet_ntop(AF_INET, &((const struct sockaddr_in *)&(handler->handler->peer))->sin_addr, (char*)out, handler->handler->peer_len));
    printf("token len: %lu\n", token_len);

    if(!quiche_version_is_supported(version))
    {
        out_len = quiche_negotiate_version(scid, scid_len, dcid, dcid_len, out, sizeof(out));

        errno = 0;
        if(sendto(handler->handler->fd, out, out_len, 0, &handler->handler->peer, handler->handler->peer_len) != out_len)
        {
            perror("sendto didn't send enough bytes");
            return false;
        }
        return false;
    }

    if(token_len == 0)
    {
        uint8_t new_scid[QUICHE_MAX_CONN_ID_LEN];
        printf("stateless retry\n");


        random_set_unsecure_seed(random_standard_seed());
        random_unsecure_bytes(new_scid, sizeof(new_scid));

        print_id(new_scid, sizeof(new_scid));

        out_len = quiche_retry(scid, scid_len, dcid, dcid_len, new_scid, sizeof(new_scid), dcid, dcid_len, version, out, sizeof(out));

        errno = 0;
        if(sendto(handler->handler->fd, out, out_len, 0, &handler->handler->peer, handler->handler->peer_len) != out_len)
        {
            perror("sendto didn't send enough bytes");
            return false;
        }
        return false;
    }

    print_id(dcid, dcid_len);

    handler->conn = quiche_accept(dcid, dcid_len, token, token_len, &handler->handler->local, handler->handler->local_len, &handler->handler->peer, handler->handler->peer_len, handler->handler->config);

    return true;
}


static bool process_ingress(QuicConnHandler* handler)
{
    int n = 0;
    uint8_t buffers[MAX_MSG_RECVMMSG][2048];
    struct iovec iovecs[MAX_MSG_RECVMMSG];
    struct mmsghdr msgs[MAX_MSG_RECVMMSG];

    struct pollfd pollfd[] = {{.fd = handler->handler->fd, .events = POLLIN}};

    int nfds = poll(pollfd, sizeof(pollfd) / sizeof(struct pollfd), handler->conn ? (int)quiche_conn_timeout_as_millis(handler->conn): -1);
    if(nfds < 0)
    {
        perror("poll");
        return false;
    }

    if(nfds == 0)
    {
        // timeout
        quiche_conn_on_timeout(handler->conn);
        return true;
    }

    for (int i = 0; i < MAX_MSG_RECVMMSG; i++) {
        iovecs[i].iov_base          = buffers[i];
        iovecs[i].iov_len           = 2048;
        msgs[i].msg_hdr.msg_iov     = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &handler->handler->peer;    // BAD !!! msgs are not guaranteed to be from the same peer
        msgs[i].msg_hdr.msg_namelen = handler->handler->peer_len;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }


    errno = 0;
    while(nfds > 0 && (n = recvmmsg(handler->handler->fd, msgs, MAX_MSG_RECVMMSG, 0, NULL)) > 0)
    {
        for(int i = 0; i < n; i++)
        {
            if(handler->conn == NULL)
            {
                if(!create_conn(handler, buffers[i], msgs[i].msg_len))
                {
                    break;
                }
            }
            quiche_recv_info recv_info = {.from = &handler->handler->peer, .from_len = handler->handler->peer_len, .to = &handler->handler->local, .to_len = handler->handler->local_len};

            if(quiche_conn_recv(handler->conn, (uint8_t*)buffers[i], msgs[i].msg_len, &recv_info) < 0)
            {
                break;
            }
        }
    }
    if(nfds > 0 && n < 0 && errno != 0 && errno != EWOULDBLOCK)
    {
        perror("recv");
        return false;
    }

    return true;
}

static bool process_egress(QuicConnHandler* handler)
{
    int nb_msgs = 0;
    ssize_t n;
    uint8_t out[MAX_MSG_SENDMMSG][MAX_DATAGRAM_SIZE];
    struct iovec iovecs[MAX_MSG_SENDMMSG];
    struct mmsghdr msgs[MAX_MSG_SENDMMSG];
    struct mmsghdr* msgs_left = msgs;

    quiche_send_info out_info;

    if(handler->conn == NULL)
    {
        return true;
    }

    while(nb_msgs < MAX_MSG_SENDMMSG && (n = quiche_conn_send(handler->conn, out[nb_msgs], MAX_DATAGRAM_SIZE, &out_info)) > 0)
    {
        iovecs[nb_msgs].iov_base          = out[nb_msgs];
        iovecs[nb_msgs].iov_len           = n;
        msgs[nb_msgs].msg_hdr.msg_iov     = &iovecs[nb_msgs];
        msgs[nb_msgs].msg_hdr.msg_iovlen  = 1;
        msgs[nb_msgs].msg_hdr.msg_name    = &handler->handler->peer;    // BAD !!! msgs are not guaranteed to be from the same peer
        msgs[nb_msgs].msg_hdr.msg_namelen = handler->handler->peer_len;
        msgs[nb_msgs].msg_hdr.msg_control = NULL;
        msgs[nb_msgs].msg_hdr.msg_controllen = 0;
        msgs[nb_msgs].msg_hdr.msg_flags = 0;

        nb_msgs++;
    }

    while(nb_msgs > 0)
    {
        errno = 0;
        int sended = sendmmsg(handler->handler->fd, msgs_left, nb_msgs, 0);
        if(sended > 0)
        {
            msgs_left += sended;
            nb_msgs -= sended;
        }
    }

    if(n < 0 && n != QUICHE_ERR_DONE)
    {
        quiche_conn_close(handler->conn, false, 0x1, (uint8_t*)"fail", 4);
        return false;
    }
    return true;
}


QuicConnHandler* quic_connect(const char* hostname, const char* port, uint32_t protocol_version, bool verify_peer)
{
    ssize_t n;
    uint8_t out[MAX_DATAGRAM_SIZE] = {0};

    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];

    QuicConnHandler* handler = NULL;

    handler = calloc(1, sizeof(QuicConnHandler));
    if(handler == NULL)
    {
        goto FREE;
    }
    handler->handler = calloc(1, sizeof(QuicBaseHandler));
    if(handler->handler == NULL)
    {
        goto FREE;
    }
    handler->handler->fd = -1;
    handler->handler->peer_len = sizeof(struct sockaddr);

    handler->handler->fd = build_socket("127.0.0.1", "0", hostname, port, &handler->handler->local, &handler->handler->local_len, &handler->handler->peer, &handler->handler->peer_len);
    if(handler->handler->fd < 0)
    {
        goto FREE;
    }

    if(!set_blocking_mode(handler->handler->fd, false))
    {
        goto FREE;
    }

    handler->handler->config = quiche_config_new(protocol_version);
    if(handler->handler->config == NULL)
    {
        goto FREE;
    }

    handler->handler->h3_config = quiche_h3_config_new();
    if(handler->handler->h3_config == NULL)
    {
        goto FREE;
    }

    quiche_config_verify_peer(handler->handler->config, verify_peer);

    quiche_config_set_application_protos(handler->handler->config, QUICHE_H3_APPLICATION_PROTOCOL, sizeof(QUICHE_H3_APPLICATION_PROTOCOL)-1);

    quiche_config_set_max_idle_timeout(handler->handler->config, 5000);
    quiche_config_set_max_recv_udp_payload_size(handler->handler->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(handler->handler->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(handler->handler->config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(handler->handler->config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(handler->handler->config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(handler->handler->config, 1000000);
    quiche_config_set_initial_max_streams_bidi(handler->handler->config, 100);
    quiche_config_set_initial_max_streams_uni(handler->handler->config, 100);
    quiche_config_set_disable_active_migration(handler->handler->config, true);
    quiche_config_set_active_connection_id_limit(handler->handler->config, 2);
    quiche_config_set_max_connection_window(handler->handler->config, 25165824);
    quiche_config_set_max_stream_window(handler->handler->config, 16777216);
    quiche_config_set_cc_algorithm_name(handler->handler->config, "cubic");

    random_set_unsecure_seed(random_standard_seed());
    random_unsecure_bytes(scid, sizeof(scid));

    handler->conn = quiche_connect(hostname, (uint8_t*)scid, sizeof(scid), &handler->handler->local, handler->handler->local_len, &handler->handler->peer, handler->handler->peer_len, handler->handler->config);
    if(handler->conn == NULL)
    {
        goto FREE;
    }

    quiche_send_info out_info;

    n = quiche_conn_send(handler->conn, (uint8_t*)out, sizeof(out), &out_info);
    if(n < 0)
    {
        goto FREE;
    }
    if(send(handler->handler->fd, out, n, 0) != n)
    {
        perror("send didn't send enough bytes");
        goto FREE;
    }

    while(!quiche_conn_is_closed(handler->conn))
    {
        if(!process_ingress(handler))
        {
            goto FREE;
        }

        if(quiche_conn_is_established(handler->conn))
        {
            // connected
            handler->h3_conn = quiche_h3_conn_new_with_transport(handler->conn, handler->handler->h3_config);
            if(handler->h3_conn == NULL)
            {
                goto FREE;
            }
            return handler;
        }

        if(!process_egress(handler))
        {
            goto FREE;
        }
    }

FREE:
    quic_conn_free(&handler);
    return NULL;
}


QuicBaseHandler* quic_server_init(const char* hostname, const char* port, uint32_t protocol_version, const char* cert_path, const char* key_path)
{
    QuicBaseHandler* handler = NULL;

    handler = calloc(1, sizeof(QuicBaseHandler));
    if(handler == NULL)
    {
        goto FREE;
    }
    handler->fd = -1;
    handler->independent = true;
    handler->peer_len = sizeof(struct sockaddr);

    handler->fd = build_socket(hostname, port, NULL, NULL, &handler->local, &handler->local_len, NULL, NULL);
    if(handler->fd < 0)
    {
        goto FREE;
    }

    if(!set_blocking_mode(handler->fd, false))
    {
        goto FREE;
    }

    handler->config = quiche_config_new(protocol_version);
    if(handler->config == NULL)
    {
        goto FREE;
    }

    handler->h3_config = quiche_h3_config_new();
    if(handler->h3_config == NULL)
    {
        goto FREE;
    }

    if(quiche_config_load_cert_chain_from_pem_file(handler->config, cert_path))
    {
        fprintf(stderr, "Cannot load cert file\n");
        goto FREE;
    }
    if(quiche_config_load_priv_key_from_pem_file(handler->config, key_path))
    {
        fprintf(stderr, "Cannot load key file\n");
        goto FREE;
    }

    quiche_config_set_application_protos(handler->config, QUICHE_H3_APPLICATION_PROTOCOL, sizeof(QUICHE_H3_APPLICATION_PROTOCOL)-1);

    quiche_config_set_max_idle_timeout(handler->config, 5000);
    quiche_config_set_max_recv_udp_payload_size(handler->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(handler->config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(handler->config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(handler->config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(handler->config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(handler->config, 1000000);
    quiche_config_set_initial_max_streams_bidi(handler->config, 100);
    quiche_config_set_initial_max_streams_uni(handler->config, 100);
    quiche_config_set_disable_active_migration(handler->config, true);
    quiche_config_enable_early_data(handler->config);

    return handler;

FREE:
    quic_base_free(&handler);
    return NULL;
}

QuicConnHandler* quic_accept(QuicBaseHandler* server_handler)
{
    QuicConnHandler* handler = calloc(1, sizeof(QuicConnHandler));
    if(handler == NULL)
    {
        return NULL;
    }
    handler->handler = server_handler;

    while(handler->conn == NULL || (!quiche_conn_is_established(handler->conn) && !quiche_conn_is_in_early_data(handler->conn)))
    {
        process_ingress(handler);
        process_egress(handler);
    }
    handler->h3_conn = quiche_h3_conn_new_with_transport(handler->conn, server_handler->h3_config);

    return handler;
}

void quic_reply(QuicConnHandler* handler, uint64_t stream_id, uint8_t* content, size_t content_length)
{
    char content_length_str[256];
    snprintf(content_length_str, 256, "%lu", content_length);

    quiche_h3_header headers[] = {
        {.name = (uint8_t*)":status", .name_len = sizeof(":status")-1, .value = (uint8_t*)"200", .value_len = sizeof("200")-1},
        {.name = (uint8_t*)"server", .name_len = sizeof("server")-1, .value = (uint8_t*)"quiche", .value_len = sizeof("quiche")-1},
        {.name = (uint8_t*)"content-length", .name_len = sizeof("content-length")-1, .value = (uint8_t*)content_length_str, .value_len = strlen(content_length_str)},
    };

    quiche_conn_stream_shutdown(handler->conn, stream_id, QUICHE_SHUTDOWN_READ, 0);
    quiche_h3_send_response(handler->h3_conn, handler->conn, stream_id, headers, sizeof(headers) / sizeof(quiche_h3_header), false);
    while(content_length > 0)
    {
        for(int i = 0; i < 100; i++)
        {
            ssize_t sended = quiche_h3_send_body(handler->h3_conn, handler->conn, stream_id, content, content_length, true);
            if(sended > 0)
            {
                if((size_t)sended > content_length)
                {
                    sended = content_length;
                }
                content += sended;
                content_length -= sended;
            }
            process_egress(handler);
        }
        process_ingress(handler);
    }
    process_egress(handler);
}


int64_t quic_send_request(QuicConnHandler* handler, const char* method, const char* scheme, const char* hostname, const char* path, const char* user_agent)
{
    quiche_h3_header headers[] = {
        {.name = (uint8_t*)":method", .name_len = sizeof(":method")-1, .value = (uint8_t*)method, .value_len = strlen(method)},
        {.name = (uint8_t*)":scheme", .name_len = sizeof(":scheme")-1, .value = (uint8_t*)scheme, .value_len = strlen(scheme)},
        {.name = (uint8_t*)":authority", .name_len = sizeof(":authority")-1, .value = (uint8_t*)hostname, .value_len = strlen(hostname)},
        {.name = (uint8_t*)":path", .name_len = sizeof(":path")-1, .value = (uint8_t*)path, .value_len = strlen(path)},
        {.name = (uint8_t*)"user-agent", .name_len = sizeof("user-agent")-1, .value = (uint8_t*)user_agent, .value_len = strlen(user_agent)}
    };

    return quiche_h3_send_request(handler->h3_conn, handler->conn, headers, sizeof(headers) / sizeof(quiche_h3_header), true);
}


int64_t quic_poll(QuicConnHandler* handler, quiche_h3_event** ev)
{
    int64_t stream_id = QUICHE_H3_ERR_DONE;
    do
    {
        stream_id = quiche_h3_conn_poll(handler->h3_conn, handler->conn, ev);

        if(stream_id >= 0 || stream_id != QUICHE_H3_ERR_DONE)
        {
            return stream_id;
        }

        if(!process_egress(handler))
        {
            return QUICHE_H3_ERR_DONE;
        }
    } while(process_ingress(handler) && !quiche_conn_is_closed(handler->conn));

    return QUICHE_H3_ERR_DONE;
}


ssize_t quic_recv_body_v1(QuicConnHandler* handler, uint64_t stream_id, uint8_t *out, size_t out_len)
{
    return quiche_h3_recv_body(handler->h3_conn, handler->conn, stream_id, out, out_len);
}


void quic_close(QuicConnHandler* handler)
{
    quiche_conn_close(handler->conn, true, 0, (uint8_t*)"kthxbye", 7);
}

void quic_conn_free(QuicConnHandler** handler)
{
    if(*handler == NULL)
    {
        return;
    }

    if((*handler)->handler != NULL && !(*handler)->handler->independent)
    {
        quic_base_free(&(*handler)->handler);
    }

    if((*handler)->conn)
        quiche_conn_free((*handler)->conn);
    if((*handler)->h3_conn)
    quiche_h3_conn_free((*handler)->h3_conn);
    free(*handler);
    *handler = NULL;
}

void quic_base_free(QuicBaseHandler** handler)
{
    if(*handler == NULL)
    {
        return;
    }

    quiche_config_free((*handler)->config);
    quiche_h3_config_free((*handler)->h3_config);
    if((*handler)->fd >= 0)
    {
        close((*handler)->fd);
    }
    free(*handler);
    *handler = NULL;
}