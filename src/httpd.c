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
#include <glib.h>
#include <glib/gprintf.h>

// #define TCP_KEEPINIT 128  /* N, time to establish connection */
// #define TCP_KEEPIDLE 256  /* L,N,X start keeplives after this period */
// #define TCP_KEEPINTVL 512 /* L,N interval between keepalives */
// #define TCP_KEEPCNT 1024  /* L,N number of keepalives before close */

const int tcp_max_size = 1500;
const int file_max_length = 4096;
const int http_method_size = 10;
const int http_version_size = 9;
const int ipv4_url_max_size = 19;
const int max_connections = 200;
const char* HTTP_V1 = "HTTP/1.1";
const char* HTTP_V0 = "HTTP/1.0";
const char *html_start = "<!DOCTYPE html>\n<html lang=\"en\">\n\t<head>\n\t\t<title>HTTP Server response</title>\n\t\t<meta charset=\"UTF-8\">\n\t\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\t</head>\n\t<body>\n\t\t";
const char *html_end = "\n\t</body>\n</html>\n";
FILE *log_file = NULL;

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

GString* get_header_field_value(GString* header, char* header_field)
{
    // Split the header and get the length
    gchar** fields = g_strsplit(header->str, "\r\n", -1);
    guint len = g_strv_length(fields);

    // Lowercase the header field input for comparison
    gchar* lowercase_header_field = g_ascii_strdown(header_field, -1);

    gchar** field_split = NULL;
    GString* field_value = NULL;
    gchar* lowercased = NULL;

    // Start at the first field
    for(guint i = 1; i < len; i++)
    {   
        // Split the header field into name and value
        field_split = g_strsplit(fields[i], ":", 2);

        if (field_split == NULL)
        {
            continue;
        }

        // Lowercase the field name for comparison
        lowercased = g_ascii_strdown(field_split[0], -1);

        if (g_strcmp0(lowercase_header_field, lowercased) == 0)
        {   
            // Field found. Trim whitespace, lowercase and assign the field value
            g_strstrip(field_split[1]);
            gchar* lowercased_value = g_ascii_strdown(field_split[1], -1); 

            field_value = g_string_new(lowercased_value);

            g_free(lowercased_value);
            break;
        }
        
        g_free(lowercased);
        g_strfreev(field_split);

        field_split = NULL;
        lowercased = NULL;
    }

    g_free(lowercased);
    g_free(lowercase_header_field);
    g_strfreev(field_split);
    g_strfreev(fields);

    return field_value;
}

bool is_keep_alive(GString* header, GString* http_version)
{
    GString* connection_value = get_header_field_value(header, "Connection");
    bool keep_alive = false;

    // Connection header exists
    if (connection_value != NULL)
    {
        if (g_strcmp0(connection_value->str, "keep-alive") == 0)
        {
            keep_alive = true;
        }

        g_string_free(connection_value, TRUE);
    }
    // HTTP Version
    else
    {
        if (g_strcmp0(http_version->str, HTTP_V1) == 0)
        {
            keep_alive = true;
        }
    }

    return keep_alive;
}

void parse_message(char* message, GString** header, GString** body, GString** http_method, GString** requested_url, GString** http_version)
{   
    // Split message into header and body by two CLRF's in a row
    gchar** split = g_strsplit(message, "\r\n\r\n", 2);

    // Assign header and body
    *header = g_string_new(split[0]);
    *body = g_string_new(split[1]);

    g_strfreev(split);
    split = NULL;

    // Split the header into the status line and header fields
    split = g_strsplit((*header)->str, "\r\n", 2);
    gchar** status_line_split = g_strsplit(split[0], " ", 3);

    g_strfreev(split);
    split = NULL;

    // Assign the HTTP Method and requested URL
    *http_method = g_string_new(status_line_split[0]);
    *requested_url = g_string_new(status_line_split[1]);

    // Split the HTTP version into the actual version and CLRF
    split = g_strsplit(status_line_split[2], "\r\n", 2);

    g_strfreev(status_line_split);
    status_line_split = NULL;

    // Assign the HTTP version
    *http_version = g_string_new(split[0]);

    g_strfreev(split);
    split = NULL;
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

void add_body(GString** header, GString* body)
{
    g_string_append_printf(*header, "\r\n%s", body->str);
}

void add_header_field(GString** header, char* field_name, char* field_value)
{
    g_string_append_printf(*header, "\r\n%s: %s ", field_name, field_value);
}

GString* create_header(const char* http_version, const int http_code, const char* http_phrase)
{
    GString* header = g_string_new("");
    g_string_printf(header, "%s %d %s", http_version, http_code, http_phrase);

    return header;
}

GString* create_html(struct sockaddr_in server, struct sockaddr_in client, GString* requested_url, GString* body)
{
    // Get the port of server
    int server_port;
    get_port(server, &server_port);

    // Get the IPv4 address and port of client
    int client_ip1, client_ip2, client_ip3, client_ip4, client_port;
    get_ip(client, &client_ip1, &client_ip2, &client_ip3, &client_ip4);
    get_port(client, &client_port);

    GString* html = g_string_new("");
    GString* server_URL = g_string_new("");
    GString* client_URL = g_string_new("");

    g_string_printf(server_URL, "localhost:%d", server_port);
    g_string_printf(client_URL, "%d.%d.%d.%d:%d", client_ip1, client_ip2, client_ip3, client_ip4, client_port);

    g_string_printf(html, "%shttp://%s%s %s", html_start, server_URL->str, requested_url->str, client_URL->str);

    if (body != NULL)
    {
        g_string_append_printf(html, "\n%s", body->str);
    }

    g_string_append_printf(html, "%s", html_end);

    g_string_free(server_URL, TRUE);
    g_string_free(client_URL, TRUE);

    return html;
}

GString* create_response(bool is_head, struct sockaddr_in server, struct sockaddr_in client, GString* requested_url, GString* body, bool keep_alive)
{
    GString* html = create_html(server, client, requested_url, body);

    GString* html_size = g_string_new("");
    g_string_printf(html_size, "%lu", html->len);

    GString* header = create_header(HTTP_V1, 200, "OK");

    add_header_field(&header, "Content-Length", html_size->str);
    add_header_field(&header, "Content-Type", "text/html");

    if (!keep_alive)
    {
        add_header_field(&header, "Connection", "close");
    }

    header = g_string_append(header, "\r\n");

    if (!is_head)
    {
        add_body(&header, html);
    }
    else
    {
        g_string_append_printf(header, "\r\n");
    }

    g_string_free(html_size, TRUE);

    return header;
}

void log_request(struct sockaddr_in client, GString* http_method, GString* requested_url, int status_code)
{
    // Get the IPv4 address and port
    int ip1, ip2, ip3, ip4, port;
    get_ip(client, &ip1, &ip2, &ip3, &ip4);
    get_port(client, &port);

    // Construct the timestamp
    // Source: https://stackoverflow.com/questions/1442116/how-to-get-date-and-time-value-in-c-program
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    GString* log_message = g_string_new("");
    g_string_printf(log_message, "%d-%02d-%02dT%02d:%02d:%02dZ : <%d.%d.%d.%d>:<%d> <%s> <%s> : <%d>", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ip1, ip2, ip3, ip4, port, http_method->str, requested_url->str, status_code);

    g_printf("%s\n", log_message->str);

    if (log_file != NULL)
    {
        fprintf(log_file, "%s\n", log_message->str);
    }
    else
    {
        printf("ERROR: Could not open log file\nErrno: %d\n", errno);
    }

    g_string_free(log_message, TRUE);
}

void handle_GET(int connfd, struct sockaddr_in server, struct sockaddr_in client, GString* http_method, GString* requested_url, bool keep_alive)
{
    GString* response = create_response(false, server, client, requested_url, NULL, keep_alive);

    log_request(client, http_method, requested_url, 200);

    send(connfd, response->str, response->len, 0);

    g_string_free(response, TRUE);
}

void handle_HEAD(int connfd, struct sockaddr_in server, struct sockaddr_in client, GString* http_method, GString* requested_url, bool keep_alive)
{
    GString* response = create_response(true, server, client, requested_url, NULL, keep_alive);

    log_request(client, http_method, requested_url, 200);

    send(connfd, response->str, response->len, 0);

    g_string_free(response, TRUE);
}

void handle_POST(int connfd, struct sockaddr_in server, struct sockaddr_in client, GString* http_method, GString* requested_url, GString* body, bool keep_alive)
{
    GString* response = create_response(false, server, client, requested_url, body, keep_alive);

    log_request(client, http_method, requested_url, 200);

    send(connfd, response->str, response->len, 0);

    g_string_free(response, TRUE);
}

void handle_other(int connfd, struct sockaddr_in client, GString* http_method, GString* requested_url)
{
    GString* response = create_header("HTTP/1.1", 501, "Unsupported");

    log_request(client, http_method, requested_url, 501);

    send(connfd, response->str, response->len, 0);

    g_string_free(response, TRUE);
}

int main(int argc, char **argv)
{
    // Verify arguments
    if (argc != 2)
    {
        g_printf("Incorrect number of arguments.\nSpecify port number.\nExiting...\n");
        return -1;
    }

    log_file = fopen("httpd_logfile", "a");
    if (log_file == NULL)
    {
        g_printf("Could not open log file.\nExiting...\n");
        return -1;
    }

    int port = atoi(argv[1]);
    int sockfd;
    int on = 1;
    int timeout;
    struct sockaddr_in server;
    socklen_t len = (socklen_t)sizeof(server);
    char message[tcp_max_size];

    // char requested_url[file_max_length];
    // char http_method[http_method_size];
    // char http_version[http_version_size];

    GString* http_method;
    GString* requested_url;
    GString* http_version;
    GString* header;
    GString* body;

    struct pollfd fds[max_connections];
    struct sockaddr_in clients[max_connections];
    int nfds = 1;
    int current_size = 0;
    bool end_server = false;
    bool close_conn = false;
    bool compress_array = false;
    bool keep_alive = false;

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        g_printf("Unable to bind the socket. errno: %d\nExiting...\n", errno);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
    {
        g_printf("setsockopt failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        return -1;
    }

    if (ioctl(sockfd, FIONBIO, (char *)&on) < 0)
    {
        g_printf("ioctl failed. errno: %d\nExiting...\n", errno);
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
            g_printf("Port number already in use: %d\n", port);
            return -1;
        }
        // Unknown error
        else
        {
            g_printf("Unknown error binding the socket. errno: %d\n", errno);
            return -1;
        }
    }

    // Before the server can accept messages, it has to listen to the
    // welcome port. A backlog of 10 connections is allowed.
    if (listen(sockfd, 10) < 0)
    {
        g_printf("listen failed. errno: %d\nExiting...\n", errno);
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
    g_printf("Listening on port %d...\n", port);

    while (!end_server)
    {

        int poll_value = poll(fds, nfds, timeout);
        if (poll_value < 0)
        {
            g_printf("poll failed. errno: %d\nExiting...\n", errno);
            break;
        }
        else if (poll_value == 0)
        {
            // Poll timeout, continue
            g_printf("Poll timeout\n");
            continue;
        }

        current_size = nfds;
        for (int i = 0; i < current_size; i++)
        {
            close_conn = false;

            // printf("Connection: %d, revents: %d\n", i, fds[i].revents);

            if (fds[i].revents == 0)
            {
                //printf("DEBUG: revents is 0, not doing shit for this one.\n");
                continue;
            }

            if (fds[i].revents & POLLHUP)
            {
                // g_printf("Client closing connection via POLLHUP...\n");
                close_conn = true;
            }

            if (fds[i].revents != POLLIN)
            {
                // g_printf("Error, revents was not POLLIN or POLLHUP\n");
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

                g_printf("Adding new connection...\n");

                if (nfds == max_connections - 1)
                {
                    g_printf("Maximum connections reached, rejecting...\n");
                    close_connection(&connfd, NULL);

                    continue;
                }

                // struct timeval timeout;
                // timeout.tv_sec = 5;
                // timeout.tv_usec = 0;
                // setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

                fds[nfds].fd = connfd;
                fds[nfds].events = POLLIN | POLLHUP;
                nfds++;
            }
            else
            {
                close_conn = false;
                keep_alive = false;
                memset(&message, 0, sizeof(message));

                ssize_t n = recv(fds[i].fd, message, sizeof(message) - 1, 0);

                // int max = 1000;
                // printf("\n=== DEBUG MESSAGE ===\n");
                
                // printf("%s", message);

                // printf("\n============\n\n");

                // printf("DEBUG: Received:\n%s\n", message);

                if (n <= 0)
                {
                    if (n == 0)
                    {
                        g_printf("Client closed connection.\n");
                    }
                    else if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        // Timeout -> close connection
                        g_printf("Client timed out, closing connection...\n");
                    }
                    else
                    {
                        g_printf("recv failed. Unknown error. errno: %d\nClosing connection...\n", errno);
                    }

                    close_conn = true;
                }
                else
                {
                    // TODO: VALIDATE MESSAGE

                    parse_message(message, &header, &body,&http_method, &requested_url, &http_version);
                    keep_alive = is_keep_alive(header, http_version);
                    close_conn = !keep_alive;

                    // GET Request
                    if (g_strcmp0(http_method->str, "GET") == 0)
                    {
                        handle_GET(fds[i].fd, server, clients[i], http_method, requested_url, keep_alive);
                    }
                    // HEAD Request
                    else if (g_strcmp0(http_method->str, "HEAD") == 0)
                    {
                        handle_HEAD(fds[i].fd, server, clients[i], http_method, requested_url, keep_alive);
                    }
                    // POST Request
                    else if (g_strcmp0(http_method->str, "POST") == 0)
                    {
                        handle_POST(fds[i].fd, server, clients[i], http_method, requested_url, body, keep_alive);
                    }
                    // Not supported request
                    else
                    {
                        printf("DEBUG: Unsupported request\n");
                        handle_other(fds[i].fd, clients[i], http_method, requested_url);
                        close_conn = true;
                    }

                    g_string_free(header, TRUE);
                    g_string_free(body, TRUE);
                    g_string_free(http_method, TRUE);
                    g_string_free(requested_url, TRUE);
                    g_string_free(http_version, TRUE);
                }

                if (close_conn)
                {
                    // printf("Connection closed.\n");
                    close_connection(&fds[i].fd, &compress_array);
                }
            }
        }

        if (compress_array)
        {
            //printf("Number of fds: %d. Compressing array...\n", nfds);
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
            //printf("Number of fds: %d\n", nfds);
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
            close_connection(&fds[i].fd, NULL);
        }
    }

    fclose(log_file);

    return 0;
}
