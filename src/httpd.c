/* A TCP echo server.
 *
 * Receive a message on port 32000, turn it into upper case and return
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <glib.h>

const int tcp_max_size = 1500;
const int file_max_length = 4096;
const int http_method_size = 10;

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

void getIPPort(struct sockaddr_in addr, int *ip1, int *ip2, int *ip3, int *ip4, int *port)
{
    *ip1 = addr.sin_addr.s_addr & 0xFF;
    *ip2 = (addr.sin_addr.s_addr >> 8) & 0xFF;
    *ip3 = (addr.sin_addr.s_addr >> 16) & 0xFF;
    *ip4 = (addr.sin_addr.s_addr >> 24) & 0xFF;

    *port = (addr.sin_port & 0xFF) << 8;
    *port = *port | ((addr.sin_port >> 8) & 0xFF);
}

void logRequest(struct sockaddr_in client, char *http_method, char *requested_url, int status_code)
{
    int logMessageSize = 64 + strlen(http_method) + strlen(requested_url);
    int count;
    bool success = false;
    char *logMessage = malloc(logMessageSize);
    memset(logMessage, 0, logMessageSize);

    // Get the IPv4 address and port
    int ip1, ip2, ip3, ip4, port;
    getIPPort(client, &ip1, &ip2, &ip3, &ip4, &port);

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

void handle_GET(struct sockaddr_in client, char *http_method, char *requested_url)
{
    logRequest(client, http_method, requested_url, 200);
}

void handle_HEAD(struct sockaddr_in client, char *http_method, char *requested_url)
{
    logRequest(client, http_method, requested_url, 200);
}

void handle_POST(struct sockaddr_in client, char *http_method, char *requested_url)
{
    logRequest(client, http_method, requested_url, 200);
}

void handle_other(struct sockaddr_in client, char *http_method, char *requested_url)
{
    logRequest(client, http_method, requested_url, 501);
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
    struct sockaddr_in server, client;
    char message[tcp_max_size];
    char requested_url[file_max_length];
    char http_method[http_method_size];

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

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
    // welcome port. A backlog of one connection is allowed.
    listen(sockfd, 1);

    // Notify that the server is ready
    printf("Listening on port %d...\n", port);

    for (;;)
    {
        // We first have to accept a TCP connection, connfd is a fresh
        // handle dedicated to this connection.
        socklen_t len = (socklen_t)sizeof(client);
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
                handle_GET(client, http_method, requested_url);
            }
            // HEAD Request
            else if (strcmp(http_method, "HEAD") == 0)
            {
                handle_HEAD(client, http_method, requested_url);
            }
            // POST Request
            else if (strcmp(http_method, "POST") == 0)
            {
                handle_POST(client, http_method, requested_url);
            }
            // Not supported request
            else
            {
                handle_other(client, http_method, requested_url);
            }

            message[n] = '\0';
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
    }
}
