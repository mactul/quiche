#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/http_utils.h"
#include "common/quic_helper.h"


int main(int argc, char* argv[])
{
    http_utils_UrlSplitted url = {.host = "127.0.0.1", .port = "4433", .secured = true, .req = "/test.md"};
    int return_code = 1;

    int64_t stream_id;
    quiche_h3_event* ev;
    size_t total_received = 0;

    QuicConnHandler* handler = NULL;

    if(argc > 1)
    {
        if(!http_utils_parse_url(argv[1], &url))
        {
            fprintf(stderr, "Invalid URL provided");
            goto FREE;
        }
    }


    handler = quic_connect(url.host, url.port, QUICHE_PROTOCOL_VERSION, false);
    if(handler == NULL)
    {
        goto FREE;
    }

    printf("connected\n");

    if(quic_send_request(handler, "GET", url.secured ? "https" : "http", url.host, url.req, "quiche") < 0)
    {
        goto FREE;
    }

    while((stream_id = quic_poll(handler, &ev)) >= 0)
    {
        switch(quiche_h3_event_type(ev))
        {
            case QUICHE_H3_EVENT_HEADERS:
                printf("headers received\n");
                break;
            case QUICHE_H3_EVENT_DATA:
                {
                    ssize_t read;
                    uint8_t data[BUFSIZ];
                    while((read = quic_recv_body_v1(handler, stream_id, data, sizeof(data))) > 0)
                    {
                        // write(STDOUT_FILENO, data, read);
                        total_received += read;
                    }
                }
                break;
            case QUICHE_H3_EVENT_FINISHED:
                quic_close(handler);
        }
        quiche_h3_event_free(ev);
    }

    printf("\nTotal received: %lu\n", total_received);

    return_code = 0;
FREE:
    quic_conn_free(&handler);
    return return_code;
}