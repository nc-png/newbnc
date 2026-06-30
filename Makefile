CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -g
LDFLAGS :=

TARGETS := ftpbnc genconfig

all: $(TARGETS)

ftpbnc: ftpbnc.o
	$(CC) $(CFLAGS) -o ftpbnc ftpbnc.o $(LDFLAGS)

ftpbnc.o: ftpbnc.c
	$(CC) $(CFLAGS) -c ftpbnc.c

genconfig: genconfig.o
	$(CC) $(CFLAGS) -o genconfig genconfig.o -lcrypto

genconfig.o: genconfig.c
	$(CC) $(CFLAGS) -c genconfig.c

clean:
	rm -f $(TARGETS) *.o

