CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
OBJDEPS = utils.o api.o algorithm.o vector.o \
      fdset.o email.o treap.o
OBJ = client_gmenghani ODR_gmenghani server_gmenghani $(OBJDEPS)

LINKFLAGS = -lpthread
INCFLAGS  = -I /home/users/cse533/Stevens/unpv13e/lib/
LIBS      = /home/users/cse533/Stevens/unpv13e/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: $(OBJ)

ODR_gmenghani: odr.c odr.h api.h myassert.h gitcommit.h $(OBJDEPS)
	$(CC) $(CFLAGS) odr.c  $(OBJDEPS) -o ODR_gmenghani $(LIBS)

client_gmenghani: timecli.c myassert.h gitcommit.h $(OBJDEPS)
	$(CC) $(CFLAGS) timecli.c $(OBJDEPS) -o client_gmenghani $(LIBS)

server_gmenghani: timeserv.c myassert.h gitcommit.h $(OBJDEPS)
	$(CC) $(CFLAGS) timeserv.c $(OBJDEPS) -o server_gmenghani $(LIBS)

api.o: api.c api.h utils.h
	$(CC) $(CFLAGS) -c -o api.o api.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c

fdset.o: fdset.c fdset.h vector.h algorithm.h utils.o myassert.h
	$(CC) $(CFLAGS) -c -o fdset.o fdset.c

vector.o: vector.c vector.h myassert.h
	$(CC) $(CFLAGS) -c -o vector.o vector.c

algorithm.o: algorithm.c algorithm.h vector.h myassert.h
	$(CC) $(CFLAGS) -c -o algorithm.o algorithm.c

email.o: email.c email.h
	$(CC) $(CFLAGS) -c -o email.o email.c

treap.o: treap.c treap.h myassert.h
	$(CC) $(CFLAGS) -c -o treap.o treap.c

scp:
	./make_gitcommit.sh
	./scp.sh

handin:
	ls *.c *.h Makefile README | xargs ~cse533/handin -r Asgn3

clean:
	rm -f $(OBJ)
