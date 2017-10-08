CC = gcc
CPPFLAGS =
CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2 `pkg-config --cflags glib-2.0`
LDFLAGS =
LOADLIBES =
OBJFILES = header_parser/html.tab.o header_parser/lex.yy.o
LDLIBS = `pkg-config --libs glib-2.0`

.DEFAULT: all
.PHONY: all
all: httpd

httpd: httpd.c $(OBJFILES)
	$(CC) $(CFLAGS) -o httpd httpd.c $(OBJFILES) $(LDLIBS)

clean:
	rm -f *.o

distclean: clean
	rm -f httpd
	rm -rf *.dSYM

debug: CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -DDEBUG -g
debug: all
