#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/http_utils.h"
#include "common/quic_helper.h"

uint8_t data[1000*1000*1000];


static int callback(uint8_t *name, size_t name_len, uint8_t *value, size_t value_len, void *argp)
{
    write(STDOUT_FILENO, name, name_len);
    write(STDOUT_FILENO, " : ", 3);
    write(STDOUT_FILENO, value, value_len);
    write(STDOUT_FILENO, "\n", 1);

    return 0;
}

int main(int argc, char* argv[])
{
    http_utils_UrlSplitted url = {.host = "127.0.0.1", .port = "4433", .secured = true, .req = "/test.md"};
    int return_code = 1;

    int64_t stream_id;
    quiche_h3_event* ev;

    QuicBaseHandler* server_handler = NULL;
    QuicConnHandler* client_handler = NULL;

    if(argc > 1)
    {
        if(!http_utils_parse_url(argv[1], &url))
        {
            fprintf(stderr, "Invalid URL provided");
            goto FREE;
        }
    }

    for(size_t i = 0; i < sizeof(data); i++)
    {
        data[i] = 'A' + i % 26;
    }

    printf("data loaded\n");


    server_handler = quic_server_init(url.host, url.port, QUICHE_PROTOCOL_VERSION, "./cert.crt", "./cert.key");
    if(server_handler == NULL)
    {
        goto FREE;
    }

    client_handler = quic_accept(server_handler);
    if(client_handler == NULL)
    {
        goto FREE;
    }

    while((stream_id = quic_poll(client_handler, &ev)) >= 0)
    {
        switch(quiche_h3_event_type(ev))
        {
            case QUICHE_H3_EVENT_HEADERS:
                printf("headers received\n");
                quiche_h3_event_for_each_header(ev, callback, NULL);
                quic_reply(client_handler, stream_id, data, sizeof(data));
                break;
            default:
                printf("%d\n", quiche_h3_event_type(ev));
                break;
        }
        quiche_h3_event_free(ev);
    }
    printf("stream id: %ld\n", stream_id);

    return_code = 0;
FREE:
    quic_conn_free(&client_handler);
    quic_base_free(&server_handler);
    return return_code;
}