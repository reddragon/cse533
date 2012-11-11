CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
OBJ = timecli odr utils.o api.o

LINKFLAGS = -lpthread
INCFLAGS  = -I../unpv13e_linux/lib
LIBS      = ../unpv13e_linux/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

all: targets

debug: CFLAGS += -DDEBUG -g
debug: targets

targets: $(OBJ)

odr: odr.c odr.h utils.o api.h
	$(CC) $(CFLAGS) odr.c utils.o -o odr $(LIBS)

api.o: api.c api.h
	$(CC) $(CFLAGS) -c -o api.o api.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c

timecli: timecli.c utils.o api.o
	$(CC) $(CFLAGS) timecli.c utils.o api.o -o timecli $(LIBS)

clean:
	rm -f $(OBJ)
