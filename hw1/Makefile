CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g

all: server client echocli timecli

server: server.c util.c util.h
	$(CC) $(CFLAGS) server.c util.c -o server

client: client.c util.c util.c
	$(CC) $(CFLAGS) client.c util.c -o client

echocli: echocli.c util.h util.c
	$(CC) $(CFLAGS) echocli.c util.c -o echocli 

timecli: timecli.c util.h util.c
	$(CC) $(CFLAGS) timecli.c util.c -o timecli 

clean:
	rm client echocli timecli server 
	rm -rf *.dSYM

