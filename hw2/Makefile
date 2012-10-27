CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
INCFLAGS = -I/home/courses/cse533/Stevens/unpv13e_solaris2.10/lib
LIBS = /home/courses/cse533/Stevens/unpv13e_solaris2.10/libunp.a -lm
OBJ = client server vector.o utils.o fdset.o algorithm.o swindow.o rwindow.o
ALLOBJDEPS = vector.o utils.o fdset.o algorithm.o treap.o swindow.o rwindow.o

PLATFORM=${shell uname}

# On Linux, we assume that the folder unpv13e_linux is available in
# the parent directory.
ifeq ($(PLATFORM), Linux)
	LINKFLAGS = -lpthread
	INCFLAGS  = -I../unpv13e_linux/lib
	LIBS      = ../unpv13e_linux/libunp.a -lpthread
endif

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: server client

server: server.c utils.h $(ALLOBJDEPS)
	$(CC) $(CFLAGS) server.c $(ALLOBJDEPS) -o server $(LIBS)
client: client.c utils.h $(ALLOBJDEPS)
	$(CC) $(CFLAGS) client.c $(ALLOBJDEPS) -o client $(LIBS)
utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c
rwindow.o: rwindow.h rwindow.c
	$(CC) $(CFLAGS) -c -o rwindow.o rwindow.c
fdset.o: fdset.c fdset.h
	$(CC) $(CFLAGS) -c -o fdset.o fdset.c
vector.o: vector.c vector.h
	$(CC) $(CFLAGS) -c -o vector.o vector.c
algorithm.o: algorithm.c algorithm.h vector.h
	$(CC) $(CFLAGS) -c -o algorithm.o algorithm.c
treap.o: treap.c treap.h
	$(CC) $(CFLAGS) -c -o treap.o treap.c
swindow.o: swindow.c swindow.h treap.h
	$(CC) $(CFLAGS) -c -o swindow.o swindow.c
test:
	$(CC) $(CFLAGS) -o treap.test treap.c -DTEST -g
clean:
	rm $(OBJ)

