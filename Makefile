# Infilter Makefile

PREFIX?=/usr/local

all: infilter

infilter: main.c
	$(CC) -o $@ $<

install: all
	install -D --mode=755 infilter ${DESTDIR}${PREFIX}/bin/infilter

clean:
	rm -f infilter
