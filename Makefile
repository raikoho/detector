CC=gcc
CFLAGS=-Wall -g

all: detector

detector: main.c core.c modules/ShadowCFI.c
	$(CC) $(CFLAGS) -o detector main.c core.c modules/ShadowCFI.c

clean:
	rm -f detector
