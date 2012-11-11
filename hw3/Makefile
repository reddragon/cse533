CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -g
OBJ = odr utils.o

LINKFLAGS = -lpthread
INCFLAGS  = -I../unpv13e_linux/lib
LIBS      = ../unpv13e_linux/libunp.a -lpthread -lm

CFLAGS += $(INCFLAGS)

all: targets

#debug: CFLAGS += -DDEBUG -g
#debug: targets

targets: $(OBJ)

odr: odr.c utils.o
	$(CC) $(CFLAGS) odr.c utils.o -o odr $(LIBS)

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c -o utils.o utils.c

clean:
	rm -f $(OBJ)