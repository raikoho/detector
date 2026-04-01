CC=gcc
CFLAGS=-Wall -g

all: detector

detector: main.c core.c modules/cfi.c
	$(CC) $(CFLAGS) -o detector main.c core.c modules/cfi.c

clean:
	rm -f detector
