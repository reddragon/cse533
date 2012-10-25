CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
INCFLAGS = -I/home/courses/cse533/Stevens/unpv13e_solaris2.10/lib
LIBS = /home/courses/cse533/Stevens/unpv13e_solaris2.10/libunp.a
OBJ = client server vector.o utils.o fdset.o algorithm.o

PLATFORM=${shell uname}

# On Linux, we assume that the folder unpv13e_linux is available in
# the parent directory.
ifeq ($(PLATFORM), Linux)
	LINKFLAGS = -lpthread
	INCFLAGS  = -I../unpv13e_linux/lib
	LIBS      = ../unpv13e_linux/libunp.a
endif

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: server client

server: server.c utils.h utils.o fdset.o vector.o algorithm.o
	$(CC) $(CFLAGS) server.c utils.o fdset.o vector.o algorithm.o -o server $(LIBS)
client: client.c utils.h utils.o fdset.o vector.o algorithm.o
	$(CC) $(CFLAGS) client.c utils.o fdset.o vector.o algorithm.o -o client $(LIBS)
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c
fdset.o: fdset.c fdset.h
	$(CC) $(CFLAGS) -c -o fdset.o fdset.c
vector.o: vector.c vector.h
	$(CC) $(CFLAGS) -c -o vector.o vector.c
algorithm.o: algorithm.c algorithm.h vector.h
	$(CC) $(CFLAGS) -c -o algorithm.o algorithm.c
treap.o: treap.c
	$(CC) $(CFLAGS) -c -o treap.o treap.c
test:
	$(CC) $(CFLAGS) -o treap.test treap.c -DTEST
clean:
	rm $(OBJ)

