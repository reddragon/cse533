CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g -fpack-struct
OBJDEPS = utils.o api.o algorithm.o vector.o \
      fdset.o treap.o
OBJ = gmenghani_tour gmenghani_arp $(OBJDEPS)

LINKFLAGS = -lpthread
INCFLAGS  = -I /home/users/cse533/Stevens/unpv13e/lib/
LIBS      = /home/users/cse533/Stevens/unpv13e/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: $(OBJ)

gmenghani_tour: tour.c api.h myassert.h $(OBJDEPS)
	$(CC) $(CFLAGS) tour.c $(OBJDEPS) -o gmenghani_tour $(LIBS)

gmenghani_arp: arp.c myassert.h $(OBJDEPS)
	$(CC) $(CFLAGS) arp.c $(OBJDEPS) -o gmenghani_arp $(LIBS)

fdset.o: fdset.c fdset.h vector.h algorithm.h utils.o myassert.h
	$(CC) $(CFLAGS) -c -o fdset.o fdset.c

vector.o: vector.c vector.h myassert.h
	$(CC) $(CFLAGS) -c -o vector.o vector.c

api.o: api.c api.h utils.h myassert.h
	$(CC) $(CFLAGS) -c -o api.o api.c

utils.o: utils.c utils.h myassert.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c

algorithm.o: algorithm.c algorithm.h vector.h myassert.h
	$(CC) $(CFLAGS) -c -o algorithm.o algorithm.c

treap.o: treap.c treap.h myassert.h
	$(CC) $(CFLAGS) -c -o treap.o treap.c

scp:
	./scp.sh

handin:
	ls *.c *.h Makefile README | xargs ~cse533/handin -r Asgn4

clean:
	rm -f $(OBJ)

