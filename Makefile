# Infilter Makefile

PREFIX?=/usr/local

all: infilter

infilter: main.c
	$(CC) -o $@ $<

.PHONY: install
install: all
	install -D --mode=755 infilter ${DESTDIR}${PREFIX}/bin/infilter

.PHONY: test
test: infilter
	@uv sync
	@uv run pytest -v

.PHONY: clean
clean:
	rm -f infilter
