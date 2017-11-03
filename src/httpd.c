/* A TCP HTTP Server.
 * Poll code based on https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_71/rzab6/poll.htm
 * Use of Flex and Bison for the HTTP Parser are subject to the GPL-3.0 License.
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
#include <signal.h>

/* === Enums ===*/
typedef enum { TEST, COLOR, LOGIN, SECRET, OTHER } page_type;

/* === Structs === */
struct client {
    struct sockaddr_in sockaddr;
    gint64 last_heard;
    bool keep_alive;
};

struct http_request {
    GHashTable* header_fields;
    GHashTable* query_parameters;
    char* host;
    page_type page;
    GString* http_method;
    GString* requested_url;
    GString* http_version;
    GString* header;
    GString* body;
};

/* === Destroy functions === */
void free_destroyed(gpointer data)
{
    free(data);
}

/* === Global variables, mostly constants ===*/
const int message_buffer_size = 100 * 1024; // Size of the message buffer
#define max_connections 300 // Maximum number of clients. Needs to be define instead of const due to the struct fds
const int max_listen = 64; // Maximum number of clients in the listen backlog
const int recv_timeout_seconds = 5; // Timout of clients in recv calls
const gint64 max_keep_alive_time = 30 * G_USEC_PER_SEC; // Maximum keep-alive time, 30 seconds in microseconds
struct pollfd fds[max_connections]; // Poll file descriptors array for clients
int nfds = 1; // Number of file descriptors in the fds array (number of clients)
const int poll_timeout = (30 * 1000); // The timeout of the poll, 30 seconds
const char* HTTP_V1 = "HTTP/1.1"; // HTTP version 1.1
const char* HTTP_V0 = "HTTP/1.0"; // HTTP version 1.0
const char *html_start = "<!DOCTYPE html>\n<html lang=\"en\">\n\t<head>\n\t\t<title>HTTP Server response</title>\n\t\t<meta charset=\"UTF-8\">\n\t\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\t</head>\n\t<body>\n\t\t";
const char *html_end = "\n\t</body>\n</html>\n";
FILE *log_file = NULL; // Log file pointer

// HTTP Parser stuff
bool VALID = false; // HTTP Parser valid flag, needs to be global
extern void yyparse(); // HTTP Parser function call
extern void yyrestart(FILE* input_file); // To reset the parser

/*
 * Extract the IPv4 address form a struct sockaddr_in
 */
void get_ip(struct sockaddr_in addr, int *ip1, int *ip2, int *ip3, int *ip4)
{
    *ip1 = addr.sin_addr.s_addr & 0xFF;
    *ip2 = (addr.sin_addr.s_addr >> 8) & 0xFF;
    *ip3 = (addr.sin_addr.s_addr >> 16) & 0xFF;
    *ip4 = (addr.sin_addr.s_addr >> 24) & 0xFF;
}

/*
 * Extract the port form a struct sockaddr_in
 */
void get_port(struct sockaddr_in addr, int *port)
{
    *port = (addr.sin_port & 0xFF) << 8;
    *port = *port | ((addr.sin_port >> 8) & 0xFF);
}

/*
 * Shutdown and close a specific function.
 * If compress array is not null, sets it to true
 */
void close_connection(int *connfd, bool *compress_arr)
{
    shutdown(*connfd, SHUT_RDWR);
    close(*connfd);
    *connfd = -1;

    if (compress_arr != NULL)
    {
        *compress_arr = true;
    }
}

/*
 * Closes all connections and the log file, then exits the program
 */
void clean_up()
{
    for (int i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
        {
            close_connection(&fds[i].fd, NULL);
        }
    }

    fclose(log_file);

    exit(0);
}

/*
 * Checks all the keep-alive times and closes the connection
 * if it should not be alive any more as per the maximum keep-alive time
 */
void check_keep_alives(struct client* clients, bool* compress_arr)
{
    // Get the current time
    gint64 current_time = g_get_real_time();
    for (int i = 1; i < nfds; i++)
    {
        // Only check open keep-alive connections
        if (fds[i].fd != -1 && clients[i].last_heard != 0)
        {
            // Get the difference
            gint64 diff = current_time - clients[i].last_heard;

            // Close the connection if it matches or is above the maximum keep-alive time
            if (max_keep_alive_time <= diff)
            {
                close_connection(&fds[i].fd, compress_arr);
            }
        }
    }
}

/*
 * Shift all the arrays in order to re-use them
 */
void compress_array(bool* compress_arr, struct client* clients)
{
    *compress_arr = false;
    for (int i = 0; i < nfds; i++)
    {
        // Shift closed connections away
        if (fds[i].fd == -1)
        {
            for (int j = i; j < nfds; j++)
            {
                fds[j].fd = fds[j + 1].fd;
                clients[j] = clients[j + 1];
            }
            i--;
            nfds--;
        }
    }
}

/*
 * Check if the connection should be keep-alive
 */
bool is_keep_alive(struct http_request request)
{
    // Get the Connection header field value
    char* connection_value = (char*) g_hash_table_lookup(request.header_fields, "connection");
    bool keep_alive = false;

    // Connection header exists
    if (connection_value != NULL)
    {
        gchar* lowercased = g_ascii_strdown(connection_value, -1);

        if (g_strcmp0(lowercased, "keep-alive") == 0)
        {
            keep_alive = true;
        }

        g_free(lowercased);
    }
    // HTTP Version
    else
    {
        // Set to keep alive if HTTP/1.1
        if (g_strcmp0(request.http_version->str, HTTP_V1) == 0)
        {
            keep_alive = true;
        }
    }

    return keep_alive;
}

void create_query_parameters_hashmap(struct http_request* request)
{
    // Split the URL to get the query part
    gchar** query_part = g_strsplit(request->requested_url->str, "?", 2);

    g_printf("Number of query parameters: %d\n", g_strv_length(query_part));

    if (g_strv_length(query_part) != 2)
    {
        g_strfreev(query_part);
        return;
    }

    gchar** queries = g_strsplit(query_part[1], "&", -1);

    g_strfreev(query_part);

    guint len = g_strv_length(queries);

    request->query_parameters = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify) free_destroyed, (GDestroyNotify) free_destroyed);

    gchar** query_split = NULL;

    // Start at the first query parameter
    for(guint i = 0; i < len; i++)
    {   
        // Split the query parameter into key and value
        query_split = g_strsplit(queries[i], "=", 2);

        if (query_split == NULL)
        {
            g_printf("Split null, ignoring\n");
            continue;
        }

        if (g_strv_length(query_split) == 2)
        {
            char* key = g_strdup(query_split[0]);
            char* value = g_strdup(query_split[1]);

            g_printf("Adding '%s' with value '%s'\n", key, value);
            g_hash_table_insert(request->query_parameters, key, value);
        }
        else
        {
            char* key = g_strdup(query_split[0]);

            g_printf("Adding '%s' with empty string\n", key);
            g_hash_table_insert(request->query_parameters, key, "");
        }
        
        g_strfreev(query_split);

        query_split = NULL;
    }

    if (query_split != NULL)
    {
        g_strfreev(query_split);
    }

    if (queries != NULL)
    {
        g_strfreev(queries);
    }
}

void create_header_fields_hashmap(struct http_request* request)
{
    // Split the header and get the length
    gchar** fields = g_strsplit(request->header->str, "\r\n", -1);
    guint len = g_strv_length(fields);

    request->header_fields = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify) free_destroyed, (GDestroyNotify) free_destroyed);

    gchar** field_split = NULL;

    // Start at the first field
    for(guint i = 1; i < len; i++)
    {   
        // Split the header field into name and value
        field_split = g_strsplit(fields[i], ":", 2);

        if (field_split == NULL)
        {
            continue;
        }

        //Lowercase the field name
        char* lowercased_key = g_ascii_strdown(field_split[0], -1);
        char* value = g_strstrip(g_strdup(field_split[1]));

        g_printf("Adding header field '%s' with value '%s'\n", lowercased_key, value);

        g_hash_table_insert(request->header_fields, lowercased_key, value);
        
        g_strfreev(field_split);

        field_split = NULL;
    }

    g_strfreev(field_split);
    g_strfreev(fields);
}

/*
 * Parse the HTTP header and make sure it is valid.
 * Extracts the header, body, HTTP method, requested URL and HTTP version as allocated GStrings
 * Returns whether or not the message is valid, if not, nothing it allocated.
 */
bool parse_message(char* message, struct http_request* request)
{
    // Split message into header and body by two CLRF's in a row
    gchar** split = g_strsplit(message, "\r\n\r\n", 2);

    if (split == NULL && split[0] == NULL)
    {
        return false;
    }

    // Add the double CLRF's to the header and parse
    GString* complete_header = g_string_new(split[0]);
    g_string_append_printf(complete_header, "\r\n\r\n");

    // Parser sets the VALID bool.
    extern FILE* yyin;
    yyin = fmemopen(complete_header->str, complete_header->len, "r");
    yyrestart(yyin);
    yyparse();
    fclose(yyin);

    g_string_free(complete_header, TRUE);

    if (!VALID)
    {
        g_strfreev(split);
        return false;
    }

    // Assign header and body
    request->header = g_string_new(split[0]);
    request->body = g_string_new(split[1]);

    g_strfreev(split);
    split = NULL;

    // Split the header into the status line and header fields
    split = g_strsplit(request->header->str, "\r\n", 2);
    gchar** status_line_split = g_strsplit(split[0], " ", 3);

    g_strfreev(split);
    split = NULL;

    // Assign the HTTP Method and requested URL
    request->http_method = g_string_new(status_line_split[0]);
    request->requested_url = g_string_new(status_line_split[1]);

    // Get the page type
    if (request->requested_url != NULL)
    {
        gchar* lowercased = g_ascii_strdown(request->requested_url->str, -1);

        if (g_str_has_prefix(lowercased, "/test"))
        {
            request->page = TEST;
        }
        else
        {
            request->page = OTHER;
        }

        g_free(lowercased);
    }

    // Split the HTTP version into the actual version and CLRF
    split = g_strsplit(status_line_split[2], "\r\n", 2);

    g_strfreev(status_line_split);
    status_line_split = NULL;

    // Assign the HTTP version
    request->http_version = g_string_new(split[0]);

    g_strfreev(split);

    return true;
}

/*
 * Append the body to the header
 */
void add_body(GString** header, GString* body)
{
    g_string_append_printf(*header, "\r\n%s", body->str);
}

/*
 * Add a header field with value to the header
 */
void add_header_field(GString** header, char* field_name, char* field_value)
{
    g_string_append_printf(*header, "\r\n%s: %s ", field_name, field_value);
}

/*
 * Create the HTTP header with a status line
 */
GString* create_header(const char* http_version, const int http_code, const char* http_phrase)
{
    GString* header = g_string_new("");
    g_string_printf(header, "%s %d %s", http_version, http_code, http_phrase);

    return header;
}

/*
 * Create the HTML "file" with an optional custom body
 */
GString* create_html(bool is_post, struct sockaddr_in server, struct client client, struct http_request request)
{
    // Get the port of server
    int server_port;
    get_port(server, &server_port);

    // Get the IPv4 address and port of client
    int client_ip1, client_ip2, client_ip3, client_ip4, client_port;
    get_ip(client.sockaddr, &client_ip1, &client_ip2, &client_ip3, &client_ip4);
    get_port(client.sockaddr, &client_port);

    GString* html = g_string_new("");
    GString* server_URL = g_string_new("");
    GString* client_URL = g_string_new("");

    // Construct the server URL
    if (request.host != NULL)
    {
        g_string_printf(server_URL, "%s", request.host);
    }
    // If Host header is not provided, default to localhost
    else
    {
        g_string_printf(server_URL, "localhosty:%d", server_port);
    }

    // Construct the client URL
    g_string_printf(client_URL, "%d.%d.%d.%d:%d", client_ip1, client_ip2, client_ip3, client_ip4, client_port);

    // Construct the initial body
    g_string_printf(html, "%shttp://%s%s %s", html_start, server_URL->str, request.requested_url->str, client_URL->str);

    // Append a custom body if post
    if (is_post)
    {
        g_string_append_printf(html, "\n%s", request.body->str);
    }
    else if (request.page == TEST && request.query_parameters != NULL)
    {
        GHashTableIter iter;
        gpointer key, value;
        
        g_hash_table_iter_init (&iter, request.query_parameters);
        while (g_hash_table_iter_next (&iter, &key, &value))
        {
            g_string_append_printf(html, "\n%s: %s", (char*) key, (char*) value);
        }
    }

    // Append the HTML end
    g_string_append_printf(html, "%s", html_end);

    g_string_free(server_URL, TRUE);
    g_string_free(client_URL, TRUE);

    return html;
}

/*
 * Create a response to the client
 * This function takes care of creating the HTML and adding the
 * Content-Length, Content-Type and Connection:close if this is not keep-alive.
 * Adds the HTML file to the message body of the response if not a HEAD request
 */
GString* create_response(bool is_head, bool is_post, struct sockaddr_in server, struct client client, struct http_request request)
{
    // Create HTML
    GString* html = create_html(is_post, server, client, request);

    // Get the HTML size as "char bytes"
    GString* html_size = g_string_new("");
    g_string_printf(html_size, "%lu", html->len);

    // Create the initial header
    GString* header = create_header(HTTP_V1, 200, "OK");

    // Add Content-Length
    add_header_field(&header, "Content-Length", html_size->str);
    
    // Add Content-Type 
    add_header_field(&header, "Content-Type", "text/html");

    // Add Connection: close if not a keep-alive
    if (!client.keep_alive)
    {
        add_header_field(&header, "Connection", "close");
    }
    else
    {
        add_header_field(&header, "Connection", "keep-alive");
    }

    // Append a CLRF to the header
    header = g_string_append(header, "\r\n");

    // Append to the body the HTML file if not HEAD
    if (!is_head)
    {
        add_body(&header, html);
    }
    // Append a CLRF as the body if a HEAD request
    else
    {
        g_string_append_printf(header, "\r\n");
    }

    g_string_free(html, TRUE);
    g_string_free(html_size, TRUE);

    return header;
}

/*
 * Logs a request to the log file
 * Constructs the log message
 */
void log_request(struct client client, struct http_request request, int status_code)
{
    // Get the IPv4 address and port
    int ip1, ip2, ip3, ip4, port;
    get_ip(client.sockaddr, &ip1, &ip2, &ip3, &ip4);
    get_port(client.sockaddr, &port);

    // Construct the timestamp
    // Source: https://stackoverflow.com/questions/1442116/how-to-get-date-and-time-value-in-c-program
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    // Construct the timestamp and client IP/port
    GString* log_message = g_string_new("");
    g_string_printf(log_message, "%d-%02d-%02dT%02d:%02d:%02dZ : <%d.%d.%d.%d>:<%d>", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ip1, ip2, ip3, ip4, port);
    
    // Bad request
    if (request.http_method == NULL)
    {
        g_string_append_printf(log_message, " <> <> : <%d>", status_code);
    }
    else
    {
        g_string_append_printf(log_message, " <%s> <%s> : <%d>", request.http_method->str, request.requested_url->str, status_code);
    }

    // Log the message, the log file pointer should be open over the course of the program
    fprintf(log_file, "%s\n", log_message->str);

    g_string_free(log_message, TRUE);
}

/*
 * Handles a GET request
 * Creates, sends the response and logs the request
 */
void handle_GET(int connfd, struct sockaddr_in server, struct client client, struct http_request request)
{
    // Create response
    GString* response = create_response(false, false, server, client, request);

    // Send response
    send(connfd, response->str, response->len, 0);

    // Log request
    log_request(client, request, 200);

    g_string_free(response, TRUE);
}

/*
 * Handles a HEAD request
 * Creates, sends the response and logs the request
 */
void handle_HEAD(int connfd, struct sockaddr_in server, struct client client, struct http_request request)
{
    // Create response
    GString* response = create_response(true, false, server, client, request);

    // Send response
    send(connfd, response->str, response->len, 0);

    // Log request
    log_request(client, request, 200);

    g_string_free(response, TRUE);
}

/*
 * Handles a GET request.
 * Creates, sends the response and logs the request
 */
void handle_POST(int connfd, struct sockaddr_in server, struct client client, struct http_request request)
{
    // Create response
    GString* response = create_response(false, true, server, client, request);

    // Send response
    send(connfd, response->str, response->len, 0);

    // Log request
    log_request(client, request, 200);

    g_string_free(response, TRUE);
}

/*
 * Handles an unsupported request.
 * Creates, sends the response and logs the request
 */
void handle_other(int connfd, struct client client, struct http_request request)
{
    // Create response
    GString* response = create_header(HTTP_V1, 501, "Not supported");
    g_string_append_printf(response, "\r\n");

    // Send response
    send(connfd, response->str, response->len, 0);

    // Log request
    log_request(client, request, 501);

    g_string_free(response, TRUE);
}

/*
 * Handles a bad request due to parse errors.
 * Creates, sends the response and logs the request
 */
void handle_bad_request(int connfd, struct client client, struct http_request request)
{
    // Create response
    GString* response = create_header(HTTP_V1, 400, "Bad request");
    g_string_append_printf(response, "\r\n");

    // Send response
    send(connfd, response->str, response->len, 0);

    // Log request
    log_request(client, request, 400);

    g_string_free(response, TRUE);
}

/*
 * Serve a client
 * Validates and parses a request
 * Determines if a request is keep-alive
 * Uses one of the handle_X functions based on the request
 */
void serve_client(int* client_fd, bool* compress_arr, struct sockaddr_in server, struct client* client)
{
    bool close_conn = false;

    struct http_request request;
    request.header_fields = NULL;
    request.query_parameters = NULL;
    request.http_method = NULL;
    request.requested_url = NULL;
    request.http_version = NULL;
    request.header = NULL;
    request.host = NULL;
    request.body = NULL;

    char message[message_buffer_size];
    memset(&message, 0, sizeof(message));
    
    // Get data from client
    ssize_t n = recv(*client_fd, message, sizeof(message) - 1, 0);

    // Close if client sent an empty message
    if (n <= 0)
    {
        close_conn = true;
    }
    else
    {
        // Validate and parse
        bool valid = parse_message(message, &request);
        
        // Bad request if not valid
        if (!valid)
        {
            handle_bad_request(*client_fd, *client, request);
            close_conn = true;
        }
        // Valid request
        else
        {
            create_header_fields_hashmap(&request);
            create_query_parameters_hashmap(&request);

            // Determine if the request is keep-alive
            client->keep_alive = is_keep_alive(request);
            close_conn = !client->keep_alive;

            if (g_strcmp0(request.http_version->str, HTTP_V1) != 0 && g_strcmp0(request.http_version->str, HTTP_V0) != 0)
            {
                handle_other(*client_fd, *client, request);
                close_conn = true;
            }
            else
            {
                // Get the Host header field
                request.host = (char*) g_hash_table_lookup(request.header_fields, "host");

                // GET Request
                if (g_strcmp0(request.http_method->str, "GET") == 0)
                {
                    handle_GET(*client_fd, server, *client, request);
                }
                // HEAD Request
                else if (g_strcmp0(request.http_method->str, "HEAD") == 0)
                {
                    handle_HEAD(*client_fd, server, *client, request);
                }
                // POST Request
                else if (g_strcmp0(request.http_method->str, "POST") == 0)
                {
                    handle_POST(*client_fd, server, *client, request);
                }
                // Not supported request
                else
                {
                    handle_other(*client_fd, *client, request);
                    close_conn = true;
                }
            }

            if (request.header != NULL)
            {
                g_string_free(request.header, TRUE);
            }

            if (request.body != NULL)
            {
                g_string_free(request.body, TRUE);
            }

            if (request.http_method != NULL)
            {
                g_string_free(request.http_method, TRUE);
            }

            if (request.requested_url != NULL)
            {
                g_string_free(request.requested_url, TRUE);
            }

            if (request.http_version != NULL)
            {
                g_string_free(request.http_version, TRUE);
            }

            if (request.header_fields != NULL)
            {
                g_hash_table_destroy(request.header_fields);
            }

            if (request.query_parameters != NULL)
            {
                g_hash_table_destroy(request.query_parameters);
            }
        }
    }

    // Close a connection if flag is set
    if (close_conn)
    {
        close_connection(client_fd, compress_arr);
    }
    // Do not close connection
    else
    {
        // Store the current time for this client
        client->last_heard = g_get_real_time();
    }
}

/*
 * Add a new client
 * Determines if the client buffer is full and if so, rejects the client.
 */
void add_client(int sockfd, socklen_t len, struct client* clients)
{
    // Accept a client
    int connfd = accept(sockfd, (struct sockaddr *)&clients[nfds].sockaddr, &len);

    // Check for error
    if (connfd < 0)
    {
        // If not timeout, something went horribly wrong
        if (errno != EWOULDBLOCK)
        {
            printf("accept failed. Unknown error. errno: %d\nExiting...\n", errno);
            clean_up();
        }

        return;
    }

    // At maximum capacity, reject client
    if (nfds == max_connections - 1)
    {
        close_connection(&connfd, NULL);

        return;
    }

    // Set the recv timeout
    struct timeval timeout;
    timeout.tv_sec = recv_timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    // Add the client
    clients[nfds].keep_alive = false;
    clients[nfds].last_heard = 0;
    fds[nfds].fd = connfd;
    fds[nfds].events = POLLIN;
    nfds++;
}

/*
 * Check all the clients for activity
 */
void check_clients(bool* compress_arr, struct client* clients, struct sockaddr_in server, int sockfd)
{
    int current_size = nfds;
    bool close_conn = false;
    socklen_t len = (socklen_t)sizeof(server);

    // Loop over all the clients
    for (int i = 0; i < current_size; i++)
    {
        close_conn = false;

        // Do nothing if nothing happend
        if (fds[i].revents == 0)
        {
            continue;
        }

        // Reject all clients that polled out with something else than POLLIN
        if (fds[i].revents != POLLIN)
        {
            close_conn = true;
        }

        // Close connection if flag is set and move onto the next client
        if (close_conn)
        {
            close_connection(&fds[i].fd, compress_arr);

            continue;
        }

        // Add client if new connection
        if (fds[i].fd == sockfd)
        {
            add_client(sockfd, len, clients);
        }
        // Serve client if existing connection
        else
        {
            serve_client(&fds[i].fd, compress_arr, server, &clients[i]);
        }
    }

    // Compress the arrays if the flag is set, only set if a connection was closed
    if (*compress_arr)
    {
        compress_array(compress_arr, clients);
    }
}

/*
 * Run the server loop
 * Polls for activity, adds and serves clients
 */
void run_loop(struct client* clients, struct sockaddr_in server, int sockfd)
{
    bool compress_arr = false;
    
    while (true)
    {
        int poll_value = poll(fds, nfds, poll_timeout);
        if (poll_value < 0)
        {
            g_printf("poll failed. errno: %d\nExiting...\n", errno);
            break;
        }

        // Check keep-alive times
        check_keep_alives(clients, &compress_arr);

        // If any client was closed due to keep-alive, compress the arrays
        if (compress_arr)
        {
            compress_array(&compress_arr, clients);
        }

        // Check the clients if poll did not timeout
        if (poll_value != 0)
        {
            check_clients(&compress_arr, clients, server, sockfd);
        }
    }
}

/*
 * SIGINT handler.
 * Calls the clean up function before the program ends.
 */
void sigint_handler()
{
    clean_up();   
}

/*
 * The main function
 * Initializes the server and starts the server loop
 */
int main(int argc, char **argv)
{
    // Verify arguments
    if (argc != 2)
    {
        g_printf("Incorrect number of arguments.\nSpecify port number.\nExiting...\n");
        return -1;
    }

    // Open the log file
    log_file = fopen("httpd_logfile", "a");
    if (log_file == NULL)
    {
        g_printf("Could not open log file.\nExiting...\n");
        return -1;
    }

    // Assign the SIGINT signal handler for clean-up if CTRL-C
    signal(SIGINT, sigint_handler);

    int port = atoi(argv[1]); // The port
    int sockfd; // The Listen socket
    int on = 1; // Only uses for setting SO_REUSEADDR on the listen socket
    struct sockaddr_in server; // The server sockaddr

    struct client clients[max_connections]; // Client sockaddr's
   //gint64 keep_alive_times[max_connections]; // Keep-alive times for client

    // Create and bind a TCP socket.
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        g_printf("Unable to bind the socket. errno: %d\nExiting...\n", errno);
        return -1;
    }

    // Allow the listen socket to be re-usable
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
    {
        g_printf("setsockopt failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        return -1;
    }

    // Set the listening socket to be non-blocking as well as other connections
    // that originate from this socket
    if (ioctl(sockfd, FIONBIO, (char *)&on) < 0)
    {
        g_printf("ioctl failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        exit(-1);
    }

    // Set the server configurations
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

    // Before the server can accept messages, it has to listen to the welcome port.
    if (listen(sockfd, max_listen) < 0)
    {
        g_printf("listen failed. errno: %d\nExiting...\n", errno);
        close(sockfd);
        return -1;
    }

    // Clear the client arrays
    memset(fds, 0, sizeof(fds));
    memset(clients, 0, sizeof(clients));
    //memset(keep_alive_times, 0, sizeof(keep_alive_times));

    // Set the listening socket
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    // Notify that the server is ready
    g_printf("Listening on port %d...\n", port);

    // Run the server loop
    run_loop(clients, server, sockfd);

    // Clean up the server if control reaches here
    clean_up();

    return 0;
}
