/* A TCP echo server.
printf("%s\n", body);
char *body = message[i];
ge on port 32000, turn it into upper case and return
 * it to the sender. With timeout.
 *
 * Copyright (c) 2016, Marcel Kyas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Reykjavik University nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MARCEL
 * KYAS NOR REYKJAVIK UNIVERSITY BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

// #define TCP_KEEPINIT 128  /* N, time to establish connection */
// #define TCP_KEEPIDLE 256  /* L,N,X start keeplives after this period */
// #define TCP_KEEPINTVL 512 /* L,N interval between keepalives */
// #define TCP_KEEPCNT 1024  /* L,N number of keepalives before close */

const int tcp_max_size = 1500;
const int file_max_length = 4096;
const int http_method_size = 10;
const int ipv4_url_max_size = 19;
const int max_connections = 200;

/*void print_RRQ_message(char *filename, )
{
    // Construct the IPv4 address
    int ip1, ip2, ip3, ip4;
    ip1 = client.sin_addr.s_addr & 0xFF;
    ip2 = (client.sin_addr.s_addr >> 8) & 0xFF;
    ip3 = (client.sin_addr.s_addr >> 16) & 0xFF;
    ip4 = (client.sin_addr.s_addr >> 24) & 0xFF;

    // Construct the port
    int port = (client.sin_port & 0xFF) << 8;
    port = port | ((client.sin_port >> 8) & 0xFF);

    // Print
    printf("file \"%s\" requested from %d.%d.%d.%d:%d\n", filename, ip1, ip2, ip3, ip4, port);
}*/

// Source: https://stackoverflow.com/questions/31426420/configuring-tcp-keepalive-after-accept
// void enable_keepalive(int sock)
// {
//     int yes = 1;
//     setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

//     int idle = 1;
//     setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));

//     int interval = 1;
//     setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));

//     int maxpkt = 10;
//     setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int));
// }

void close_connection(int *connfd, bool *compress_array)
{
    shutdown(*connfd, SHUT_RDWR);
    close(*connfd);
    *connfd = -1;

    if (compress_array != NULL)
    {
        *compress_array = true;
    }
}

void get_ip(struct sockaddr_in addr, int *ip1, int *ip2, int *ip3, int *ip4)
{
    *ip1 = addr.sin_addr.s_addr & 0xFF;
    *ip2 = (addr.sin_addr.s_addr >> 8) & 0xFF;
    *ip3 = (addr.sin_addr.s_addr >> 16) & 0xFF;
    *ip4 = (addr.sin_addr.s_addr >> 24) & 0xFF;
}

void get_port(struct sockaddr_in addr, int *port)
{
    *port = (addr.sin_port & 0xFF) << 8;
    *port = *port | ((addr.sin_port >> 8) & 0xFF);
}

char *get_message_body(char *message, ssize_t n)
{
    // Find 2 consecutive new-lines
    message[n] = '\0';
    int i;
    for (i = 0; i < n; i++)
    {
        if (message[i] == '\n' && message[i + 1] == '\n')
        {
            i += 2;
            break;
        }
    }

    char *body = message + i;

    return body;
}

void add_body(char **header, char *body)
{
    *header = realloc(*header, 5 + strlen(*header) + strlen(body));

    strcat(*header, "\r\n");
    strcat(*header, body);
}

void add_header_field(char **header, char *field_name, char *field_value)
{
    *header = realloc(*header, 5 + strlen(*header) + strlen(field_name) + strlen(field_value));

    strcat(*header, "\r\n");
    strcat(*header, field_name);
    strcat(*header, ": ");
    strcat(*header, field_value);
}

char *create_header(char *http_version, char *http_code, char *http_phrase)
{
    char *header = calloc(5 + strlen(http_version) + strlen(http_code) + strlen(http_phrase), 1);

    strcpy(header, http_version);
    strcat(header, " ");
    strcat(header, http_code);
    strcat(header, " ");
    strcat(header, http_phrase);

    return header;
}

char *create_html(struct sockaddr_in server, struct sockaddr_in client, char *requested_url, char *message_body)
{
    char *html_start = "<!DOCTYPE html>\n<html lang=\"en\">\n\t<head>\n\t\t<title>HTTP Server response</title>\n\t\t<meta charset=\"UTF-8\">\n\t\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\t</head>\n\t<body>\n\t\t";
    char *html_end = "\n\t</body>\n</html>";
    char server_URL[ipv4_url_max_size];
    char client_URL[ipv4_url_max_size];

    int message_body_size = (message_body == NULL ? 0 : strlen(message_body) + 1);
    char *body_content = calloc(43 + strlen(requested_url) + message_body_size, 1);

    // Get the port of server
    int server_port;
    get_port(server, &server_port);

    // Get the IPv4 address and port of client
    int client_ip1, client_ip2, client_ip3, client_ip4, client_port;
    get_ip(client, &client_ip1, &client_ip2, &client_ip3, &client_ip4);
    get_port(client, &client_port);

    snprintf(server_URL, ipv4_url_max_size, "localhost:%d", server_port);
    snprintf(client_URL, ipv4_url_max_size, "%d.%d.%d.%d:%d", client_ip1, client_ip2, client_ip3, client_ip4, client_port);

    strcpy(body_content, "http://");
    strcat(body_content, server_URL);
    strcat(body_content, requested_url);
    strcat(body_content, " ");
    strcat(body_content, client_URL);

    if (message_body != NULL)
    {
        strcat(body_content, "\r\n");
        strcat(body_content, message_body);
    }

    char *html_complete = calloc(strlen(html_start) + strlen(body_content) + strlen(html_end) + 1, 1);

    strcpy(html_complete, html_start);
    strcat(html_complete, body_content);
    strcat(html_complete, html_end);

    return html_complete;
}

char *create_response(bool is_head, struct sockaddr_in server, struct sockaddr_in client, char *requested_url, char *message_body)
{
    char html_size[1024];

    char *html = create_html(server, client, requested_url, message_body);

    snprintf(html_size, strlen(html), "%d", (int)strlen(html));

    char *header = create_header("HTTP/1.1", "200", "OK");

    add_header_field(&header, "Content-Length", html_size);
    add_header_field(&header, "Content-Type", "text/html");
    strcat(header, "\r\n");

    if (!is_head)
    {
        add_body(&header, html);
    }

    return header;
}

void log_request(struct sockaddr_in client, char *http_method, char *requested_url, int status_code)
{
    int logMessageSize = 64 + strlen(http_method) + strlen(requested_url);
    int count;
    bool success = false;
    char *logMessage = calloc(logMessageSize, 1);

    // Get the IPv4 address and port
    int ip1, ip2, ip3, ip4, port;
    get_ip(client, &ip1, &ip2, &ip3, &ip4);
    get_port(client, &port);

    // Construct the timestamp
    // Source: https://stackoverflow.com/questions/1442116/how-to-get-date-and-time-value-in-c-program
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    count = snprintf(logMessage, logMessageSize, "%d-%02d-%02dT%02d:%02d:%02dZ : ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (0 <= count && count <= logMessageSize)
    {
        // Construct the IP and port
        count += snprintf(logMessage + count, logMessageSize - count, "<%d.%d.%d.%d>:<%d> ", ip1, ip2, ip3, ip4, port);

        if (0 <= count && count <= logMessageSize)
        {
            // Construct the HTTP method, request URL and response code
            count = snprintf(logMessage + count, logMessageSize - count, "<%s> <%s> : <%d>", http_method, requested_url, status_code);
            success = true;
        }
    }

    if (success)
    {
        printf("%s\n", logMessage);

        FILE *fp = NULL;
        fp = fopen("httpd_logfile", "a");

        if (fp != NULL)
        {
            fprintf(fp, "%s\n", logMessage);
            fclose(fp);
        }
        else
        {
            printf("ERROR: Could not open log file\nErrno: %d\n", errno);
        }
    }
    else
    {
        printf("ERROR: Could not construct log message\n");
    }

    free(logMessage);
}

void handle_GET(int connfd, struct sockaddr_in server, struct sockaddr_in client, char *http_method, char *requested_url)
{
    char *header = create_response(false, server, client, requested_url, NULL);

    log_request(client, http_method, requested_url, 200);

    send(connfd, header, strlen(header), 0);

    free(header);
}

void handle_HEAD(int connfd, struct sockaddr_in server, struct sockaddr_in client, char *http_method, char *requested_url)
{
    char *header = create_response(true, server, client, requested_url, NULL);

    log_request(client, http_method, requested_url, 200);

    send(connfd, header, strlen(header), 0);

    free(header);
}

void handle_POST(int connfd, struct sockaddr_in server, struct sockaddr_in client, char *http_method, char *requested_url, char *message, ssize_t n)
{
    char *message_body = get_message_body(message, n);

    char *header = create_response(false, server, client, requested_url, message_body);

    log_request(client, http_method, requested_url, 200);

    send(connfd, header, strlen(header), 0);

    free(header);
}

void handle_other(int connfd, struct sockaddr_in client, char *http_method, char *requested_url)
{
    char *header = create_header("HTTP/1.1", "501", "Unsupported");

    log_request(client, http_method, requested_url, 501);

    send(connfd, header, strlen(header), 0);

    free(header);
}

int main(int argc, char **argv)
{
    // Verify arguments
    if (argc != 2)
    {
        printf("Incorrect number of arguments.\nSpecify port number.\nExiting...\n");
        return -1;
    }

    int port = atoi(argv[1]);
    int sockfd;
    int on = 1;
    int timeout;
    struct sockaddr_in server;
    socklen_t len = (socklen_t)sizeof(server);
    char message[tcp_max_size];
    char requested_url[file_max_length];
    char http_method[http_method_size];
    struct pollfd fds[max_connections];
    struct sockaddr_in clients[max_connections];
    int nfds = 1;
    int current_size = 0;
    bool end_server = false;
    bool close_conn = false;
    bool compress_array = false;

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Unable to bind the socket. errno: %d\nExiting...\n", errno);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
    {
        printf("setsockopt failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        return -1;
    }

    // Receives should timeout after 5 seconds.
    struct timeval timeout2;
    timeout2.tv_sec = 5;
    timeout2.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout2, sizeof(timeout2));

    if (ioctl(sockfd, FIONBIO, (char *)&on) < 0)
    {
        printf("ioctl failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        exit(-1);
    }

    // Network functions need arguments in network byte order instead of
    // host byte order. The macros htonl, htons convert the values.
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) != 0)
    {
        // Port in use
        if (errno == EADDRINUSE)
        {
            printf("Port number already in use: %d\n", port);
            return -1;
        }
        // Unknown error
        else
        {
            printf("Unknown error binding the socket. errno: %d\n", errno);
            return -1;
        }
    }

    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of 32 connections is allowed.
    if (listen(sockfd, max_connections - 1) < 0)
    {
        printf("listen failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        return -1;
    }

    memset(fds, 0, sizeof(fds));
    memset(clients, 0, sizeof(clients));

    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    // 10 seconds
    timeout = (10 * 1000);

    // Notify that the server is ready
    printf("Listening on port %d...\n", port);

    while (!end_server)
    {

        int poll_value = poll(fds, nfds, timeout);
        if (poll_value < 0)
        {
            printf("poll failed. errno: %d\nExiting...\n", errno);
            break;
        }
        else if (poll_value == 0)
        {
            // Poll timeout, continue
            printf("Poll timeout\n");
            continue;
        }

        current_size = nfds;
        for (int i = 0; i < current_size; i++)
        {
            close_conn = false;

            if (fds[i].revents == 0)
            {
                continue;
            }

            if (fds[i].revents & POLLHUP)
            {
                printf("Client closing connection normally...\n");
                close_conn = true;
            }

            if (fds[i].revents != POLLIN && fds[i].revents != POLLHUP && fds[i].revents != (POLLIN | POLLHUP))
            {
                printf("Error, revents was not POLLIN or POLLHUP\n");
                close_conn = true;
            }

            if (close_conn)
            {
                close_connection(&fds[i].fd, &compress_array);

                continue;
            }

            if (fds[i].fd == sockfd)
            {
                int connfd;

                do
                {
                    //struct sockaddr_in client;
                    connfd = accept(sockfd, (struct sockaddr *)&clients[nfds], &len);

                    if (connfd < 0)
                    {
                        if (errno != EWOULDBLOCK)
                        {
                            printf("accept failed. Unknown error. errno: %d\nExiting...\n", errno);
                            end_server = true;
                        }

                        break;
                    }

                    printf("Adding new connection...\n");

                    if (nfds == max_connections - 1)
                    {
                        printf("Maximum connections reached, rejecting...\n");
                        shutdown(connfd, SHUT_RDWR);

                        break;
                    }

                    struct timeval timeout;
                    timeout.tv_sec = 20;
                    timeout.tv_usec = 0;
                    setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

                    //enable_keepalive(connfd);

                    fds[nfds].fd = connfd;
                    fds[nfds].events = POLLIN;
                    nfds++;
                } while (connfd != -1);
            }
            else
            {
                while (true)
                {
                    close_conn = false;
                    memset(&message, 0, sizeof(message));
                    memset(&http_method, 0, sizeof(http_method));
                    memset(&requested_url, 0, sizeof(requested_url));

                    // struct timeval timeout2;
                    // timeout2.tv_sec = 5;
                    // timeout2.tv_usec = 0;
                    // int s = setsockopt(fds[i].fd, SOL_SOCKET, SO_RCVTIMEO, &timeout2, sizeof(timeout2));
                    // printf("Set Success: %d. tv_sec: %ld. tv_usec: %d.\n", s, timeout2.tv_sec, timeout2.tv_usec);

                    // struct timeval timeout3;
                    // socklen_t timeout_size;

                    // memset(&timeout3, 0, sizeof(timeout3));
                    // memset(&timeout_size, 0, sizeof(timeout_size));

                    // s = getsockopt(fds[i].fd, SOL_SOCKET, SO_RCVTIMEO, &timeout3, &timeout_size);
                    // printf("Get Success: %d. tv_sec: %ld. tv_usec: %d. size: %d\n", s, timeout3.tv_sec, timeout3.tv_usec, timeout_size);

                    ssize_t n = recv(fds[i].fd, message, sizeof(message) - 1, 0);

                    printf("DEBUG: Received:\n%s\n", message);

                    if (n < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            // Timeout -> close connection
                            printf("Client timed out, closing connection...\n");
                        }
                        else
                        {
                            printf("recv failed. Unknown error. errno: %d\nClosing connection...\n", errno);
                        }

                        close_conn = true;
                        break;
                    }

                    if (n == 0)
                    {
                        printf("Client closed connection.\n");
                        close_conn = true;
                        break;
                    }

                    // Assign HTTP method
                    int it = 0;
                    for (int i = 0; i < http_method_size; i++)
                    {
                        if (message[i] == ' ' || i == http_method_size - 1)
                        {
                            http_method[i] = '\0';
                            it = i + 1;
                            break;
                        }
                        else
                        {
                            http_method[i] = message[i];
                        }
                    }

                    // Assign requested URL
                    for (int i = 0; i < file_max_length; i++)
                    {
                        if (message[it] == ' ' || i == file_max_length - 1)
                        {
                            requested_url[i] = '\0';
                            break;
                        }
                        else
                        {
                            requested_url[i] = message[it];
                            it++;
                        }
                    }

                    // GET Request
                    if (strcmp(http_method, "GET") == 0)
                    {
                        handle_GET(fds[i].fd, server, clients[i], http_method, requested_url);
                    }
                    // HEAD Request
                    else if (strcmp(http_method, "HEAD") == 0)
                    {
                        handle_HEAD(fds[i].fd, server, clients[i], http_method, requested_url);
                    }
                    // POST Request
                    else if (strcmp(http_method, "POST") == 0)
                    {
                        handle_POST(fds[i].fd, server, clients[i], http_method, requested_url, message, n);
                    }
                    // Not supported request
                    else
                    {
                        printf("DEBUG: Unsupported request\n");
                        handle_other(fds[i].fd, clients[i], http_method, requested_url);
                        close_conn = true;
                    }
                }

                if (close_conn)
                {
                    printf("Connection closed.\n");
                    close_connection(&fds[i].fd, &compress_array);
                }
            }
        }

        if (compress_array)
        {
            printf("Number of fds: %d. Compressing array...\n", nfds);
            compress_array = false;
            for (int i = 0; i < nfds; i++)
            {
                if (fds[i].fd == -1)
                {
                    for (int j = i; j < nfds; j++)
                    {
                        fds[j].fd = fds[j + 1].fd;
                    }
                    i--;
                    nfds--;
                }
            }
            printf("Number of fds: %d\n", nfds);
        }

        /*
        // We first have to accept a TCP connection, connfd is a fresh
        // handle dedicated to this connection.
        int connfd = accept(sockfd, (struct sockaddr *)&client, &len);

        // Receives should timeout after 30 seconds.
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout));

        memset(&message, 0, sizeof(message));
        memset(&http_method, 0, sizeof(http_method));
        memset(&requested_url, 0, sizeof(requested_url));

        // Receive from connfd, not sockfd.
        ssize_t n = recv(connfd, message, sizeof(message) - 1, 0);

        if (n >= 0)
        {
            // Assign HTTP method
            int it = 0;
            for (int i = 0; i < http_method_size; i++)
            {
                if (message[i] == ' ' || i == http_method_size - 1)
                {
                    http_method[i] = '\0';
                    it = i + 1;
                    break;
                }
                else
                {
                    http_method[i] = message[i];
                }
            }

            // Assign requested URL
            for (int i = 0; i < file_max_length; i++)
            {
                if (message[it] == ' ' || i == file_max_length - 1)
                {
                    requested_url[i] = '\0';
                    break;
                }
                else
                {
                    requested_url[i] = message[it];
                    it++;
                }
            }

            // GET Request
            if (strcmp(http_method, "GET") == 0)
            {
                handle_GET(connfd, server, client, http_method, requested_url);
            }
            // HEAD Request
            else if (strcmp(http_method, "HEAD") == 0)
            {
                handle_HEAD(connfd, server, client, http_method, requested_url);
            }
            // POST Request
            else if (strcmp(http_method, "POST") == 0)
            {
                handle_POST(connfd, server, client, http_method, requested_url, message, n);
            }
            // Not supported request
            else
            {
                handle_other(connfd, client, http_method, requested_url);
            }

            //message[n] = '\0';
            //fprintf(stdout, "Received:\n%s\n", message);

            // Convert message to upper case.
            //for (int i = 0; i < n; ++i)
            //    message[i] = toupper(message[i]);

            // Send the message back.
            //send(connfd, message, (size_t)n, 0);
        }
        else
        {
            // Error or timeout. Check errno == EAGAIN or
            // errno == EWOULDBLOCK to check whether a timeout happened
        }

        // Close the connection.
        shutdown(connfd, SHUT_RDWR);
        close(connfd);
        */
    }

    for (int i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
        {
            shutdown(fds[i].fd, SHUT_RDWR);
            close(fds[i].fd);
        }
    }
}
