CC = gcc
CPPFLAGS =
CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2 `pkg-config --cflags glib-2.0 openssl`
LDFLAGS =
LOADLIBES =
OBJFILES = http.tab.o lex.yy.o
LDLIBS = `pkg-config --libs glib-2.0 openssl`

.DEFAULT: all
.PHONY: all
all: parse httpd clean

httpd: httpd.c $(OBJFILES)
	$(CC) $(CFLAGS) -o httpd httpd.c $(OBJFILES) $(LDLIBS)

parse: http.tab.c http.tab.h lex.yy.c
	$(CC) $(CFLAGS) -c http.tab.c lex.yy.c

clean:
	rm -f *.o

distclean: clean
	rm -f httpd
	rm -rf *.dSYM

debug: CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2 `pkg-config --cflags glib-2.0 openssl` -DDEBUG -g
debug: all
