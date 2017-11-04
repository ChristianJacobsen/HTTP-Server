# HTTPS Server

An simple HTTPS server in C.

## Features

* Specify ports
    * The first port is for unencrypted communications, the second port is for encrypted communication.
* Request logging
* Parallel connections via polling
* Persistent connections via HTTP version and/or Connection field header
* Fairness
    * The server loops over all requests and accepts only one recv per loop per client
* Custom made HTTP header parser for incoming requests
    * Made with Flex and Bison, courtesy of GNU
* SIGINT handling for handling clean-up
* HTTPS Basic authentication on two pages
* Query parameters
* Cookies
* Comments!

## Drawback
 * Multiple parts of a large request is not supported

## Getting Started

Run the Makefile in the src/ directory to build.

```
$ make
```

Run the httpd executable. (Without brackets).

```
$ ./httpd [unencrypted port] [encrypted port]
```

### Prerequisites

GCC, Glib 2.0 and a terminal emulator.

## Implementation details

### Overview

The server starts by making sure that the ports are specified, that the log file can be opened and the database exists. If the keyfile does not exist it creates it with an entry for the user `admin` with password `password`.

Afterwards the server initializes and binds the ports, exiting and reporting if any are in use, and runs an infinite loop to serve clients via polling.

When a client wants to connect the poll exits and adds the client if maximum clients hasn't been reached.

When a client wants to send a request, the server receives it, validates and parses it before actually doing any work.

Depending on the HTTP method the server acts accordingly.

The server makes sure that the client is usin SSL if requesting the pages /login and /secret by responing with a 403 forbidden if the client is not using SSL.

In order to access /secret, the client must first go to /login and be presented with a Basic authentication scheme. The server makes sure that the clients' credentials match an existing entry in the database.
Afterwards, if the user is authenticated through /login, he/she can access the /secret page.

### Technical

The server stores header fields, query parameters and cookies in hashmaps for easy access.

The database is a key-value store keyfile in Glib.

The server logs differently whether or not it's a request for the /login and /secret pages and other pages.
The logs for the /login and /secret pages are of the form `<timestamp> : <client ip>:<client port> <user>` while other pages get the form `timestamp : <client ip>:<client port> <request method> <requested URL> : <response code>`.

### Fairness

The server is fair in the way that each client only gets one recv/SSL_read call per loop.

There is a timeout for the recv/SSL_read call, so the server will never hang indefinitely for a single client.

This means that in the end, everyone gets served.

## Authenticated and private communication

Our server uses OpenSSL to perform a TCP SSL handshake with the client making all traffic between us encrypted.

The database of users on the server only has a preset of users (actually just one, admin) whose passwords have been salted and hashed multiple times.

Since we are using SSL, all traffic is encrypted and only parties with the key(s) to encrypt and decrypt the messages can verify that the message is actually from a legit source.
This prevents any unexpected information flow and certain attacks.

## HTTP Basic Authentication

The [RFC](https://tools.ietf.org/html/rfc7617#section-4) states that the Basic authentication scheme is not secure due to its SSL reliancy.

By itself it encodes the authentication credentials using Base64 and sends them in cleartext.

Base64 is a reversable decoding and is not secure for any cryptographic means.

Basic authentication is heavily susceptible to a "(wo)man-in-the-middle" attack since Base64 can be easily decoded.

The RFC also states that the dangers of Basic authentication arise if the server does not have preset usernames and passwords.
If the users are allowed to choose their own passwords it could allow for unauthorized access of documents on not only the server in question but also other systems since users tend to reuse usernames and passwords.

## Built With

* C
* GLib 2.0
* Lex/Flex
* Yacc/Bison
* OpenSSL

## Authors

* [Christian A. Jacobsen](https://github.com/ChristianJacobsen/)
* [Hilmar Tryggvason](https://github.com/Indexu/)

## Acknowledgments

* Marcel Kyas
* Richard Stallman
* [HTTP State Management Mechanism - RFC 6265](https://tools.ietf.org/html/rfc6265)
* [Uniform Resource Identifier (URI): Generic Syntax - RFC 3986](https://tools.ietf.org/html/rfc3986)
* [The 'Basic' HTTP Authentication Scheme - RFC 7617](https://tools.ietf.org/html/rfc7617)
* [Authentication - RFC 7235](http://tools.ietf.org/html/rfc7235)
* [OpenSSL Wiki - Simple TLS Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)
* [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
* [IBM - POLL](https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_71/rzab6/poll.htm)
