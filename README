# HTTP Server

An HTTP server that allows GET, HEAD and POST requests and serves an in-memory HTML file.

## Features

* Specify port
* Request logging
* Parallel connections via polling
* Persistent connections via HTTP version and/or Connection field header
* Fairness
    * The server loops over all requests and accepts only one recv per loop per client
* Custom made HTTP header parser for incoming requests
    * Made with Flex and Bison, courtesy of GNU
* SIGINT handling for handling clean-up
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
$ ./httpd [port]
```

### Prerequisites

GCC, Glib 2.0 and a terminal emulator.

## Implementation details

### Overview

The server starts by making sure that a port is specified and that the log file can be opened.

Afterwards the server initializes and binds the port, exiting and reporting if it is in use, and runs an infinite loop to serve clients via polling.

When a client wants to connect the poll exits and adds the client if maximum clients hasn't been reached.

When a client wants to send a request, the server receives it, validates and parses it before actually doing any work.

Depending on the HTTP method the server acts accordingly.

### Fairness

The server is fair in the way that each client only gets one recv call per loop.

There is a timeout for the recv call, so the server will never hang indefinitely for a single client

This means that in the end, everyone gets served.

## Built With

* C
* GLib 2.0
* Lex/Flex
* Yacc/Bison

## Authors

* [Christian A. Jacobsen](https://github.com/ChristianJacobsen/)
* [Hilmar Tryggvason](https://github.com/Indexu/)

## Acknowledgments

* Marcel Kyas
* Richard Stallman
* [Message Syntax and Routing - RFC 7230](http://tools.ietf.org/html/rfc7230)
* [Semantics and Content - RFC 7231](http://tools.ietf.org/html/rfc7231)
* [Conditional Requests - RFC 7232](http://tools.ietf.org/html/rfc7232)
* [Range Requests - RFC 7233](http://tools.ietf.org/html/rfc7233)
* [Caching - RFC 7234](http://tools.ietf.org/html/rfc7234)
* [Authentication - RFC 7235](http://tools.ietf.org/html/rfc7235)
* [IBM - POLL](https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_71/rzab6/poll.htm)