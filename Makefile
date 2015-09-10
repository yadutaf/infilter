# Infilter Makefile

all: infilter

infilter: main.c
	$(CC) -o $@ $<

clean:
	rm *.o infilter
			     
