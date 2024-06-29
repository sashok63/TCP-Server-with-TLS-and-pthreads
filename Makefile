CFLAGS = -Wall -Wextra -pthread -pedantic -g

all:
	gcc server.c -o server $(CFLAGS)