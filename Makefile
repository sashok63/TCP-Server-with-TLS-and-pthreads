CFLAGS = -Wall -Wextra -pthread -pedantic -g
LDFLAGS = -lssl -lcrypto

all:
	gcc server.c -o server $(CFLAGS) $(LDFLAGS)