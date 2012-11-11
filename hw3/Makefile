CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
OBJDEPS = utils.o api.o algorithm.o vector.o \
      fdset.o email.o
OBJ = timecli odr $(OBJDEPS)

LINKFLAGS = -lpthread
INCFLAGS  = -I../unpv13e_linux/lib
LIBS      = ../unpv13e_linux/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: $(OBJ)

odr: odr.c odr.h api.h $(OBJDEPS)
	$(CC) $(CFLAGS) odr.c  $(OBJDEPS) -o odr $(LIBS)

timecli: timecli.c utils.o $(OBJDEPS)
	$(CC) $(CFLAGS) timecli.c $(OBJDEPS) -o timecli $(LIBS)

api.o: api.c api.h
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

clean:
	rm -f $(OBJ)
